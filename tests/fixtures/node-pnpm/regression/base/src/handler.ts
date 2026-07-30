export function parseOperation(req: { body: { operation: string } }): string {
  return req.body.operation;
}
