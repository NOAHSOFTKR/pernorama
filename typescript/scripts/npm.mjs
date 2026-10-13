// Runs npm from a script. Under `npm run`, npm tells us where its CLI is,
// and running that with the current Node.js avoids a shell altogether;
// otherwise npm is found on the PATH, which on Windows needs a shell.

import { execFileSync } from 'node:child_process';

const windows = process.platform === 'win32';

/** Runs `npm <args>` in `cwd` and returns what it printed. Throws if npm fails. */
export function npm(args, cwd) {
  const cli = process.env['npm_execpath'];
  if (cli !== undefined && /npm-cli\.c?js$/.test(cli)) {
    return execFileSync(process.execPath, [cli, ...args], { cwd, encoding: 'utf8' });
  }
  if (!windows) {
    return execFileSync('npm', args, { cwd, encoding: 'utf8' });
  }
  const quoted = args.map((arg) => (/[\s"]/.test(arg) ? `"${arg.replaceAll('"', '\\"')}"` : arg));
  return execFileSync(`npm.cmd ${quoted.join(' ')}`, { cwd, encoding: 'utf8', shell: true });
}
