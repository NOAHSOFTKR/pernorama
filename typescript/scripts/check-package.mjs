// Validates what `npm publish` would upload, without publishing anything:
// the file list, the entry points, the declarations and source maps, and
// that building twice gives byte-identical output. Run after `npm run build`.

import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { npm } from './npm.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const problems = [];
const problem = (message) => problems.push(message);

function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? walk(join(dir, entry.name)) : [join(dir, entry.name)],
  );
}

const posix = (path) => path.split(sep).join('/');

if (!existsSync(join(root, 'dist', 'index.js'))) {
  console.error('dist/ is missing; run `npm run build` first');
  process.exit(1);
}

const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

// ---- what would be published -----------------------------------------------

const [pack] = JSON.parse(npm(['pack', '--dry-run', '--json', '--ignore-scripts'], root));
const published = new Set(pack.files.map((file) => file.path));

const allowedTopLevel = new Set(['package.json', 'README.md', 'CHANGELOG.md', 'LICENSE']);
for (const file of published) {
  if (!file.startsWith('dist/') && !allowedTopLevel.has(file)) {
    problem(`unexpected file in the package: ${file}`);
  }
  if (/(^|\/)(\.npmrc|\.npmtoken|\.env)|\.tsbuildinfo$|\.test\.|(^|\/)(test|src|scripts|node_modules)\//.test(file)) {
    problem(`file must not be published: ${file}`);
  }
}
for (const required of allowedTopLevel) {
  if (!published.has(required)) {
    problem(`missing from the package: ${required}`);
  }
}

// every source module is published as code, declarations and a source map
const sources = walk(join(root, 'src')).map((file) => posix(relative(join(root, 'src'), file)));
for (const source of sources) {
  const base = `dist/${source.replace(/\.ts$/, '')}`;
  for (const extension of ['.js', '.d.ts', '.js.map']) {
    if (!published.has(base + extension)) {
      problem(`missing from the package: ${base}${extension}`);
    }
  }
}
// ... and nothing in dist/ is left over from a module that no longer exists
const expectedDist = new Set(
  sources.flatMap((source) => ['.js', '.d.ts', '.js.map'].map((ext) => `dist/${source.replace(/\.ts$/, '')}${ext}`)),
);
for (const file of published) {
  if (file.startsWith('dist/') && !expectedDist.has(file)) {
    problem(`stale build output in the package: ${file}`);
  }
}

// ---- the manifest -----------------------------------------------------------

function targets(value) {
  return typeof value === 'string' ? [value] : Object.values(value ?? {}).flatMap(targets);
}
for (const target of [...targets(manifest.exports), manifest.main, manifest.types]) {
  const path = target.replace(/^\.\//, '');
  if (!published.has(path)) {
    problem(`package.json points at ${target}, which is not published`);
  }
}
if (manifest.exports?.['.']?.types === undefined) {
  problem('package.json exports["."] has no "types" condition');
}
if (Object.keys(manifest.exports?.['.'] ?? {})[0] !== 'types') {
  problem('the "types" condition must come first in exports["."]');
}
if (manifest.type !== 'module') {
  problem('package.json "type" must be "module"');
}
if (manifest.sideEffects !== false) {
  problem('package.json "sideEffects" must be false');
}
for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies', 'bundledDependencies']) {
  if (Object.keys(manifest[field] ?? {}).length > 0) {
    problem(`the core must have no runtime dependencies, but package.json has ${field}`);
  }
}
if (manifest.private === true) {
  problem('package.json is marked private');
}
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(manifest.version)) {
  problem(`package.json version is not a semantic version: ${manifest.version}`);
}
if (typeof manifest.engines?.node !== 'string') {
  problem('package.json must declare the supported Node.js versions in engines.node');
}
for (const script of Object.values(manifest.scripts ?? {})) {
  if (/npm publish|NPM_TOKEN|_authToken/.test(script)) {
    problem(`package.json scripts must not publish or carry credentials: ${script}`);
  }
}

// ---- the build output --------------------------------------------------------

for (const file of walk(join(root, 'dist'))) {
  const name = posix(relative(root, file));
  const text = readFileSync(file, 'utf8');
  if (name.endsWith('.d.ts') && /\b_(ofRules|decide|explain|decisionOf|sameDefinition|assigned|replaced|unassigned|noChange|rejected)\b/.test(text)) {
    problem(`${name} declares an internal member; is stripInternal on?`);
  }
  if (name.endsWith('.js')) {
    if (!text.includes(`//# sourceMappingURL=${name.split('/').pop()}.map`)) {
      problem(`${name} does not reference its source map`);
    }
    // (a method named `require`, as in Permission.require, is fine)
    if (/\bmodule\.exports\b|\brequire\(['"`]|\b__decorate\(/.test(text)) {
      problem(`${name} is not plain ESM`);
    }
  }
  if (name.endsWith('.js.map')) {
    const map = JSON.parse(text);
    if (!Array.isArray(map.sourcesContent) || map.sourcesContent.length !== map.sources.length) {
      problem(`${name} does not embed its sources`);
    }
  }
}

// ---- reproducibility ---------------------------------------------------------

function digest(dir) {
  const hash = createHash('sha256');
  for (const file of walk(dir).sort()) {
    hash.update(posix(relative(dir, file)));
    hash.update('\0');
    hash.update(readFileSync(file));
    hash.update('\0');
  }
  return hash.digest('hex');
}

const verifyDir = join(root, 'dist-verify');
rmSync(verifyDir, { recursive: true, force: true });
try {
  // a sibling of dist/, so that the relative paths inside the source maps are the same
  npm(['exec', '--no', '--', 'tsc', '-p', 'tsconfig.build.json', '--outDir', 'dist-verify'], root);
  const first = digest(join(root, 'dist'));
  const second = digest(verifyDir);
  if (first !== second) {
    problem(`the build is not reproducible: dist ${first} != rebuild ${second}`);
  }
  console.log(`build digest (sha256 over dist/): ${first}`);
} finally {
  rmSync(verifyDir, { recursive: true, force: true });
}

// ---- report -------------------------------------------------------------------

console.log(`${pack.name}@${pack.version}: ${pack.entryCount} files, ${pack.size} bytes packed, ${pack.unpackedSize} bytes unpacked`);
if (problems.length > 0) {
  console.error(`\npackage validation failed:\n${problems.map((p) => `  - ${p}`).join('\n')}`);
  process.exit(1);
}
console.log('package validation passed');
