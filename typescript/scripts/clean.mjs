import { rmSync } from 'node:fs';

for (const dir of ['dist', 'dist-verify', 'build']) {
  rmSync(new URL(`../${dir}`, import.meta.url), { recursive: true, force: true });
}
