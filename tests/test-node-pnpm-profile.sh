#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/devsecops-canary.yml"
FIXTURES="$ROOT/tests/fixtures/node-pnpm"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

extract_step() {
  local step_name="$1"
  ruby -ryaml -e '
    workflow = YAML.safe_load(File.read(ARGV[0]), aliases: true)
    step = workflow.fetch("jobs").values
      .flat_map { |job| job.fetch("steps", []) }
      .find { |candidate| candidate["name"] == ARGV[1] }
    abort("step not found: #{ARGV[1]}") unless step
    print step.fetch("run")
  ' "$WORKFLOW" "$step_name"
}

command -v actionlint >/dev/null || fail "actionlint is required"
command -v semgrep >/dev/null || fail "semgrep is required"
command -v jq >/dev/null || fail "jq is required"

actionlint "$ROOT"/.github/workflows/*.yml

ruby -ryaml -e '
  workflow = YAML.safe_load(File.read(ARGV[0]), aliases: true)
  inputs = workflow.fetch(workflow.key?("on") ? "on" : true).fetch("workflow_call").fetch("inputs")
  abort "default profile changed" unless inputs.dig("security-profile", "default") == "java-maven"
  abort "default Dockerfile changed" unless inputs.dig("dockerfile-path", "default") == "Dockerfile"
  abort "default context changed" unless inputs.dig("build-context", "default") == "."
' "$WORKFLOW"

if rg -n 'uses:\s+[^[:space:]]+@(main|master|v[0-9]+([.]|$))' "$WORKFLOW"; then
  fail "all actions must remain pinned by immutable SHA"
fi
if rg -n '^[[:space:]]*(pull_request_target:|secrets:\s*inherit)' "$WORKFLOW"; then
  fail "privileged PR contexts or inherited secrets are forbidden"
fi

materialize_policy="$(extract_step "Materialize trusted SaleADS policy")"
SECURITY_PROFILE=node-pnpm bash -c "$materialize_policy"
policy=/tmp/semgrep-saleads-policy.yml

semgrep scan --quiet --config "$policy" --json --output "$TMP/clean.json" "$FIXTURES/clean/src"
clean_count="$(jq '[.results[]?] | length' "$TMP/clean.json")"
[[ "$clean_count" == 0 ]] || fail "clean fixture must have no SAST findings"

run_delta_fixture() {
  local fixture="$1" expected_full="$2" expected_delta="$3"
  local repo="$TMP/$fixture-repo"
  mkdir -p "$repo"
  git -C "$repo" init -q
  git -C "$repo" config user.name "DevSecOps Fixture"
  git -C "$repo" config user.email "devsecops-fixture@example.invalid"
  cp -R "$FIXTURES/$fixture/base/." "$repo/"
  git -C "$repo" add .
  git -C "$repo" commit -qm base
  local baseline
  baseline="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" rm -rq .
  cp -R "$FIXTURES/$fixture/head/." "$repo/"
  git -C "$repo" add -A
  git -C "$repo" commit -qm head
  semgrep scan --quiet --config "$policy" --json --output "$TMP/$fixture-full.json" "$repo/src"
  (
    cd "$repo"
    semgrep scan --quiet --config "$policy" --baseline-commit "$baseline" --json \
      --output "$TMP/$fixture-delta.json" src
  )
  local full delta
  full="$(jq '[.results[]?] | length' "$TMP/$fixture-full.json")"
  delta="$(jq '[.results[]?] | length' "$TMP/$fixture-delta.json")"
  [[ "$full" == "$expected_full" ]] || fail "$fixture full SAST expected $expected_full, got $full"
  [[ "$delta" == "$expected_delta" ]] || fail "$fixture SAST delta expected $expected_delta, got $delta"
}

run_delta_fixture inherited 1 0
run_delta_fixture regression 1 1

semgrep scan --quiet --config "$policy" --sarif --output "$TMP/regression.sarif" \
  "$TMP/regression-repo/src/handler.ts"
regression_cwe="$(jq -r '
  .runs[] as $run
  | $run.results[]? as $result
  | select($result.ruleId | endswith("saleads-node-dangerous-code-evaluation"))
  | [$run.tool.driver.rules[]?
     | select(.id == $result.ruleId)
     | .properties.tags[]?
     | select(startswith("CWE-"))][0]
' "$TMP/regression.sarif")"
[[ "$regression_cwe" == "CWE-95" ]] || fail "SAST evidence must expose actionable CWE-95 metadata"
rg -q 'Remove eval/Function' "$WORKFLOW" ||
  fail "SAST annotations must include rule-specific remediation"

sca_delta_count() {
  local base="$1" head="$2"
  jq --slurpfile base "$base" '
    ([ $base[0].Results[]?.Vulnerabilities[]? | [.VulnerabilityID, .PkgName, .InstalledVersion] | @json ]) as $known
    | [.Results[]?.Vulnerabilities[]?
       | select(([.VulnerabilityID, .PkgName, .InstalledVersion] | @json) as $key
         | ($known | index($key) | not))]
    | length
  ' "$head"
}

[[ "$(sca_delta_count "$FIXTURES/clean/trivy.json" "$FIXTURES/clean/trivy.json")" == 0 ]] ||
  fail "clean SCA fixture must pass"
[[ "$(sca_delta_count "$FIXTURES/inherited/base/trivy.json" "$FIXTURES/inherited/head/trivy.json")" == 0 ]] ||
  fail "inherited SCA finding must remain nonblocking"
[[ "$(sca_delta_count "$FIXTURES/regression/base/trivy.json" "$FIXTURES/regression/head/trivy.json")" == 1 ]] ||
  fail "new vulnerable pnpm dependency must block"

validate_dependencies="$(extract_step "Validate dependency profile evidence")"
for fixture in clean inherited regression; do
  compare="$TMP/$fixture-compare"
  mkdir -p "$compare/base" "$compare/head"
  if [[ "$fixture" == clean ]]; then
    cp -R "$FIXTURES/clean/." "$compare/base/"
    cp -R "$FIXTURES/clean/." "$compare/head/"
  else
    cp -R "$FIXTURES/$fixture/base/." "$compare/base/"
    cp -R "$FIXTURES/$fixture/head/." "$compare/head/"
  fi
  : > "$TMP/$fixture-github-env"
  SECURITY_PROFILE=node-pnpm COMPARE_ROOT="$compare" RUNNER_TEMP="$TMP" \
    GITHUB_ENV="$TMP/$fixture-github-env" bash -c "$validate_dependencies"
done

stale="$TMP/stale-lock"
mkdir -p "$stale/base" "$stale/head"
cp -R "$FIXTURES/regression/base/." "$stale/base/"
cp -R "$FIXTURES/regression/head/." "$stale/head/"
cp "$stale/base/pnpm-lock.yaml" "$stale/head/pnpm-lock.yaml"
set +e
SECURITY_PROFILE=node-pnpm COMPARE_ROOT="$stale" RUNNER_TEMP="$TMP" GITHUB_ENV="$TMP/stale.env" \
  bash -c "$validate_dependencies" >/dev/null 2>&1
stale_status=$?
set -e
[[ "$stale_status" == 31 ]] || fail "dependency declaration without lock update must return POLICY_ERROR (31)"

validate_container="$(extract_step "Validate container target contract")"
mkdir -p "$TMP/container-head" "$TMP/container-base"
set +e
SECURITY_PROFILE=node-pnpm DOCKERFILE_PATH=apps/api/Dockerfile BUILD_CONTEXT=. \
  GITHUB_WORKSPACE="$TMP/container-head" BASELINE_ROOT="$TMP/container-base" GITHUB_ENV="$TMP/container.env" \
  bash -c "$validate_container" >/dev/null 2>&1
container_status=$?
set -e
[[ "$container_status" == 31 ]] || fail "missing node-pnpm container target must return POLICY_ERROR (31)"

printf 'PASS: node-pnpm profile contract, fixtures, SAST delta, SCA delta and POLICY_ERROR paths\n'
