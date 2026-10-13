// Installs the package from a locally generated tarball into throwaway
// consumer projects and uses it the way an application would: from an ES
// module, from a CommonJS module, and from TypeScript with decorators.
// Nothing is published. Run after `npm run build`.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { npm } from './npm.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
/** Runs a script with this Node.js and returns what it printed. */
function node(script, cwd) {
  return execFileSync(process.execPath, [script], { cwd, encoding: 'utf8' });
}

if (!existsSync(join(root, 'dist', 'index.js'))) {
  console.error('dist/ is missing; run `npm run build` first');
  process.exit(1);
}

const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const work = mkdtempSync(join(tmpdir(), 'pernorama-smoke-'));
const keep = process.env['PERNORAMA_SMOKE_KEEP'] === '1';

/** A consumer project with the tarball installed. */
function consumer(name, packageJson, files) {
  const dir = join(work, name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name, private: true, ...packageJson }, null, 2));
  for (const [file, content] of Object.entries(files)) {
    writeFileSync(join(dir, file), content);
  }
  npm(['install', '--no-audit', '--no-fund', '--ignore-scripts', '--no-package-lock', tarball], dir);
  return dir;
}

// What every consumer does, whichever module system it uses.
const exercise = `
  const assert = (condition, message) => { if (!condition) throw new Error('smoke test failed: ' + message); };

  const pernorama = api.Pernorama.builder().contextPolicy(api.ContextPolicy.GLOBAL_FALLBACK).build();
  const user = pernorama.newSubject(['students.*']);
  user.grant('-students.delete', 'academy:123');
  assert(api.Permission.check(user, 'students.delete') === true, 'global grant');
  assert(api.Permission.check(user, 'students.delete', 'academy:123') === false, 'contextual deny');
  assert(user.explain('students.delete', 'academy:123').decidingLayer === 'EXACT_CONTEXT', 'explanation');

  let denied;
  try { api.Permission.require(user, 'students.delete', 'academy:123'); } catch (error) { denied = error; }
  assert(denied instanceof api.PermissionDeniedException, 'require throws PermissionDeniedException');
  assert(denied instanceof Error && denied.name === 'PermissionDeniedException', 'error name');

  const plan = api.RoleGroup.builder('plan').maxAssignments(1)
    .assignmentPolicy(api.RoleAssignmentPolicy.REPLACE_EXISTING).build();
  const pro = api.Role.builder('pro').group(plan).permission('app.pro').build();
  const max = api.Role.builder('max').group(plan).permission('app.max').build();
  const assignments = pernorama.newRoleAssignments();
  assignments.assign('alice', pro);
  assert(assignments.assign('alice', max).status === 'REPLACED', 'role replacement');
  assert(assignments.subject('alice').hasPermission('app.max') === true, 'role subject');
  assert(assignments.subject('alice').hasPermission('app.pro') === false, 'replaced role');
`;

let tarball;
try {
  const [packed] = JSON.parse(npm(['pack', '--json', '--ignore-scripts', '--pack-destination', work], root));
  tarball = join(work, packed.filename);
  console.log(`packed ${packed.filename} (${packed.entryCount} files)`);

  // ---- an ES module consumer -------------------------------------------------
  const esm = consumer('esm-consumer', { type: 'module' }, {
    'index.mjs': `
      import * as api from '${manifest.name}';
      import { ContextPolicy } from '${manifest.name}';
      import { createRequire } from 'node:module';
      ${exercise}
      // one copy of the package, whichever way it is loaded: identity-compared values stay comparable
      const required = createRequire(import.meta.url)('${manifest.name}');
      assert(required.ContextPolicy === ContextPolicy, 'require() and import give the same module instance');
      assert(typeof api.default === 'undefined', 'no default export');
      console.log('esm ok: ' + Object.keys(api).length + ' exports');
    `,
    'subpath.mjs': `
      // only the documented entry points resolve
      try {
        await import('${manifest.name}/dist/permission/syntax.js');
        throw new Error('smoke test failed: an internal module is importable');
      } catch (error) {
        if (error.code !== 'ERR_PACKAGE_PATH_NOT_EXPORTED') throw error;
      }
      const { default: pkg } = await import('${manifest.name}/package.json', { with: { type: 'json' } });
      if (pkg.version !== '${manifest.version}') throw new Error('smoke test failed: wrong version installed');
      console.log('exports ok: ' + pkg.name + '@' + pkg.version);
    `,
  });
  process.stdout.write(node('index.mjs', esm));
  process.stdout.write(node('subpath.mjs', esm));

  // ---- a CommonJS consumer ---------------------------------------------------
  const cjs = consumer('cjs-consumer', { type: 'commonjs' }, {
    'index.cjs': `
      const api = require('${manifest.name}');
      ${exercise}
      console.log('cjs ok: ' + Object.keys(api).length + ' exports');
    `,
  });
  process.stdout.write(node('index.cjs', cjs));

  // ---- a TypeScript consumer, with decorators ---------------------------------
  const tsconfig = (module) => JSON.stringify({
    compilerOptions: {
      target: 'ES2022',
      module,
      moduleResolution: module,
      strict: true,
      exactOptionalPropertyTypes: true,
      noUncheckedIndexedAccess: true,
      skipLibCheck: false, // the published declarations have to stand on their own
      types: [],
      outDir: 'out',
    },
    include: ['*.ts', '*.cts'],
  }, null, 2);

  const typescriptSource = `
    import {
      createPermissionDecorators,
      MemoryPermissionSubject,
      Permission,
      PermissionDeniedException,
      PermissionRegistry,
      type PermissionSubject,
      Role,
      RoleAssignments,
    } from '${manifest.name}';

    interface Actor { readonly permissions: PermissionSubject }

    const { Perm, PermGroup } = createPermissionDecorators({
      subject: ({ args }) => (args[0] as Actor | undefined)?.permissions,
    });

    @PermGroup('users')
    class UserService {
      created = 0;

      @Perm('create')
      create(_actor: Actor, name: string): string {
        this.created++;
        return name;
      }
    }

    function fail(message: string): never { throw new Error('smoke test failed: ' + message); }

    const admin: Actor = { permissions: new MemoryPermissionSubject(['users.*']) };
    const guest: Actor = { permissions: new MemoryPermissionSubject() };
    const service = new UserService();

    if (service.create(admin, 'bob') !== 'bob') fail('a permitted call runs');
    let denied: unknown;
    try { service.create(guest, 'eve'); } catch (error) { denied = error; }
    if (!(denied instanceof PermissionDeniedException)) fail('a denied call throws');
    if (denied.requiredPermission !== 'users.create') fail('the group prefix applies');
    if (service.created !== 1) fail('a denied call has no side effect');
    if (new PermissionRegistry().register(UserService)[0]?.name !== 'users.create') fail('the registry reads the class');

    const assignments = new RoleAssignments<string>();
    assignments.assign('alice', Role.builder('reader').permission('docs.read').build());
    if (!Permission.check(assignments.subject('alice'), 'docs.read')) fail('roles');

    export const ok: boolean = true;
  `;

  const tsc = ['exec', '--no', '--', 'tsc'];
  const tsEsm = consumer('ts-esm-consumer', { type: 'module' }, {
    'tsconfig.json': tsconfig('NodeNext'),
    'index.ts': typescriptSource,
    'run.mjs': `const { ok } = await import('./out/index.js'); if (ok !== true) process.exit(1); console.log('typescript (esm) ok');`,
  });
  npm([...tsc, '-p', join(tsEsm, 'tsconfig.json')], root);
  process.stdout.write(node('run.mjs', tsEsm));

  const tsCjs = consumer('ts-cjs-consumer', { type: 'commonjs' }, {
    'tsconfig.json': tsconfig('NodeNext'),
    'index.cts': typescriptSource,
    'run.cjs': `if (require('./out/index.cjs').ok !== true) process.exit(1); console.log('typescript (commonjs) ok');`,
  });
  npm([...tsc, '-p', join(tsCjs, 'tsconfig.json')], root);
  process.stdout.write(node('run.cjs', tsCjs));

  console.log(`consumer smoke tests passed on Node.js ${process.version}`);
} catch (error) {
  console.error(error.stdout ?? '');
  console.error(error.stderr ?? error);
  console.error(`\nconsumer smoke tests FAILED (work directory kept: ${work})`);
  process.exit(1);
}
if (!keep) {
  rmSync(work, { recursive: true, force: true });
}
