import { exec } from 'node:child_process';

export function inherited(req: { query: { command: string } }): void {
  exec(req.query.command);
}
