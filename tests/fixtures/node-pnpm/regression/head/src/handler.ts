export function evaluateOperation(req: { body: { operation: string } }): unknown {
  return eval(req.body.operation);
}
