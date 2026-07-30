# shared-workflows

Centralized reusable GitHub Actions workflows for Sale-ADS.

## DevSecOps canary profiles

`.github/workflows/devsecops-canary.yml` keeps `java-maven` as its default
profile. Existing callers do not need to change and retain the previous
`Dockerfile` plus repository-root build context contract.

The opt-in `node-pnpm` profile adds:

- Trivy SCA delta over the root `pnpm-lock.yaml` and dependency declarations in
  every workspace `package.json`.
- A `POLICY_ERROR` when dependency declarations change without a regenerated
  lockfile.
- Reviewed TypeScript/JavaScript Semgrep rules with rule-specific reason,
  remediation and validation guidance.
- Explicit repository-relative Dockerfile and build-context inputs, validated
  in both the trusted base and PR HEAD before running Docker.

### Reusable workflow inputs

| Input | Required | Default | Contract |
|---|---:|---|---|
| `image-name` | yes | — | Local, non-secret image name used for both comparison images. |
| `security-profile` | no | `java-maven` | Allowlisted values: `java-maven`, `node-pnpm`. |
| `dockerfile-path` | no | `Dockerfile` | Repository-relative path; `node-pnpm` requires the regular file in base and HEAD. |
| `build-context` | no | `.` | Repository-relative directory; `node-pnpm` requires it in base and HEAD. |
| `support-contact` | no | `@andrewramirez-ciber` | Owner shown in actionable blocking messages. |

The future control-plane caller must pin the reviewed workflow commit and pass
the Node and container inputs explicitly:

```yaml
permissions:
  contents: read

jobs:
  devsecops:
    uses: Sale-ADS/shared-workflows/.github/workflows/devsecops-canary.yml@<reviewed-full-commit-sha>
    with:
      image-name: sa-devsecops-control-plane-api
      security-profile: node-pnpm
      dockerfile-path: apps/api/Dockerfile
      build-context: .
```

Call this workflow from `pull_request`, never from `pull_request_target` or
`workflow_run`, and never pass `secrets: inherit`.

### Decisions and rollback

- New High/Critical SCA or reviewed SAST regressions block.
- Findings already present in the protected base remain visible and nonblocking.
- Missing/inconsistent pnpm or container evidence fails closed as
  `POLICY_ERROR`; scanner failures remain distinct as `SCANNER_ERROR`.
- Rollback for a Node consumer is to repin it to the previous reviewed canary
  SHA and remove the opt-in inputs. Java callers are unaffected because their
  default contract did not change.

### Local policy tests

The test suite uses clean, inherited and vulnerable-regression Node fixtures.
It validates workflow syntax, immutable action pins, Semgrep baseline/delta,
Trivy delta classification, lockfile consistency and missing-container
`POLICY_ERROR` behavior without building an application:

```bash
tests/test-node-pnpm-profile.sh
```
