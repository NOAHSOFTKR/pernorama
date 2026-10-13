# Pernorama for TypeScript

`@noahsoft/pernorama` is the TypeScript SDK of
[Pernorama](https://github.com/NOAHSOFTKR/pernorama): permission nodes,
wildcards and deny rules, contexts, roles, and explanations of a
decision, with **the same answers as the Java library**. Both
implementations run the same language-neutral fixtures in
[`spec/`](../spec), so a rule set means the same thing in a Java service
and in a Node.js one.

```ts
import { MemoryPermissionSubject, Permission } from '@noahsoft/pernorama';

const user = new MemoryPermissionSubject(['users.*', '-users.delete']);

Permission.check(user, 'users.create'); // true
Permission.check(user, 'users.delete'); // false
```

The core has no runtime dependencies and is not tied to a web framework,
a database, Discord or JWT — you plug those in by implementing
`PermissionSubject`.

> **Status: `0.1.0`, pre-1.0, not yet published to npm.** The package
> name is provisional; see [Releasing](#releasing). It is versioned
> independently of the Java artifact (`0.3.0`).

- [Installation](#installation)
- [Permissions](#permissions) · [Deny rules](#deny-rules) · [Contexts](#contexts)
- [Checking without decorators](#checking-without-decorators)
- [Custom subjects](#custom-subjects)
- [Roles](#roles) · [Role assignments in a database](#role-assignments-in-a-database)
- [Explaining a decision](#explaining-a-decision)
- [Decorators](#decorators) · [Security limitations](#security-limitations)
- [Compatibility with Java](#compatibility-with-java)
- [Errors](#errors) · [Versioning](#versioning) · [Releasing](#releasing) · [Development](#development)

## Installation

Once published:

```bash
npm install @noahsoft/pernorama
```

Until then, build the tarball from this repository and install that:

```bash
cd typescript
npm ci
npm pack                       # builds, then writes noahsoft-pernorama-0.1.0.tgz
npm install /path/to/noahsoft-pernorama-0.1.0.tgz   # in your project
```

Requirements:

| | |
| --- | --- |
| Node.js | `>= 22.12` (tested on 22 and 24) |
| Module format | ES modules. CommonJS code can `require('@noahsoft/pernorama')` directly — Node.js 22.12+ loads ES modules with `require` — and gets the same module instance an `import` does. |
| TypeScript | Type declarations are included. `@Perm`/`@PermGroup` are standard decorators and need TypeScript 5.2 or later **without** `experimentalDecorators`. Everything else works without decorators. |

There is one build, not an ESM copy and a CommonJS copy, so there is no
dual-package hazard: `ContextPolicy.EXACT` is the same object however
the package was loaded.

## Permissions

A permission **node** is a dot-separated identifier: `users.create`.
Segments are letters, digits, `_` and `-`.

A granted **rule** is a node, or a wildcard that ends in `*`:

| Rule | Covers |
| --- | --- |
| `users.create` | exactly `users.create` |
| `users.*` | `users` and everything under it |
| `*` | every node |

`users.*.read` is not a rule: a wildcard is only valid as the last
segment. Nothing is permitted unless a rule covers it.

```ts
import { PermissionNode, PermissionResolver } from '@noahsoft/pernorama';

PermissionNode.isValid('users.create'); // true
PermissionNode.isValid('users.*');      // false: a rule, not a node
PermissionResolver.isValidPattern('users.*'); // true

const node = PermissionNode.of('users.profile.edit');
node.parent()?.name;       // 'users.profile'
node.isChildOf('users');   // true
```

## Deny rules

A rule prefixed with `-` denies instead of allowing. Among the rules that
cover a node, **the most specific one decides, and a deny wins a tie**:
an exact rule beats a wildcard, and a longer wildcard prefix beats a
shorter one.

```ts
const user = new MemoryPermissionSubject(['users.*', '-users.delete']);

user.hasPermission('users.create');      // true
user.hasPermission('users.delete');      // false: the exact deny is more specific
user.hasPermission('users.delete.hard'); // true: -users.delete covers only that node
```

Deny the whole subtree with `-users.delete.*`. `revoke` removes exactly
the rule that was granted; it does not carve a node out of a wildcard —
grant a deny rule for that.

## Contexts

A context is an opaque string that scopes a grant or a check, such as
`academy:123`. Pernorama compares contexts for equality and nothing
else: `academy:*` is not a wildcard and `academy` is not a parent of
`academy:123`. `null` — or leaving the argument out — means no context;
the empty string is rejected.

What a check in a context sees is decided once, by the `ContextPolicy`
of a `Pernorama` instance:

```ts
import { ContextPolicy, Pernorama } from '@noahsoft/pernorama';

const pernorama = Pernorama.builder()
  .contextPolicy(ContextPolicy.GLOBAL_FALLBACK) // the default
  .build();

const teacher = pernorama.newSubject();
teacher.grant('students.read');                  // no context: global
teacher.grant('students.edit', 'academy:123');
teacher.grant('-students.read', 'academy:999');

teacher.hasPermission('students.edit', 'academy:123'); // true
teacher.hasPermission('students.edit');                // false: only granted in academy:123
teacher.hasPermission('students.read', 'academy:123'); // true: falls back to the global grant
teacher.hasPermission('students.read', 'academy:999'); // false: the context denies it
```

- **`GLOBAL_FALLBACK`** — grants made in the checked context decide
  every node they cover, allow or deny, *even with a less specific rule
  than a global one*. Only if none of them covers the node do the grants
  without a context decide.
- **`EXACT`** — a check in a context sees only the grants made in
  exactly that context.

Under both, a check **without** a context sees only grants without one:
a grant in `academy:123` never leaks into a contextless check.

## Checking without decorators

`Permission` is the direct API. It works with any `PermissionSubject`.

```ts
import { Permission, PermissionDeniedException } from '@noahsoft/pernorama';

if (Permission.check(user, 'reports.export')) {
  // ...
}

Permission.require(user, 'students.delete', 'academy:123'); // throws if not permitted

try {
  Permission.require(user, 'students.delete', 'academy:123');
} catch (error) {
  if (error instanceof PermissionDeniedException) {
    error.requiredPermission; // 'students.delete'
    error.context;            // 'academy:123'
  }
}
```

## Custom subjects

Implement `PermissionSubject` to answer from your own storage. **A check
is synchronous**, as it is in Java: load what the subject needs, then
ask it.

```ts
import {
  type ContextPolicy,
  type PermissionExplanation,
  PermissionGrant,
  type PermissionSubject,
  UnsupportedOperationError,
} from '@noahsoft/pernorama';

class StoredSubject implements PermissionSubject {
  private constructor(
    private readonly grants: readonly PermissionGrant[],
    private readonly policy: ContextPolicy,
  ) {}

  /** The asynchronous part happens here, once. */
  static async load(db: GrantTable, userId: string, policy: ContextPolicy): Promise<StoredSubject> {
    const rows = await db.grantsOf(userId);
    return new StoredSubject(rows.map((row) => new PermissionGrant(row.rule, row.context)), policy);
  }

  hasPermission(node: string, context?: string | null): boolean {
    return this.policy.permits(this.grants, node, context);
  }

  // optional: without it, explanations of this subject only report its answer
  explain(node: string, context?: string | null): PermissionExplanation {
    return this.policy.explain(this.grants, node, context);
  }

  grant(): never {
    throw new UnsupportedOperationError('grants are changed in the database');
  }

  revoke(): never {
    throw new UnsupportedOperationError('grants are changed in the database');
  }
}
```

Use the policy of your `Pernorama` instance (`pernorama.contextPolicy`)
so that every subject treats contexts the same way.

A `hasPermission` declared `async` would return a promise, and a promise
is truthy. Everything in this package that consumes a subject therefore
requires the answer to be exactly `true` or `false`, and throws
`IllegalStateError` otherwise instead of reading it as "allowed".

## Roles

A `Role` is a named bundle of rules. `RoleAssignments` records which
roles a target holds and answers checks from them; a `RoleGroup` limits
how many roles of a kind one target may hold.

```ts
import { Pernorama, Role, RoleAssignmentPolicy, RoleGroup } from '@noahsoft/pernorama';

const plan = RoleGroup.builder('plan')
  .maxAssignments(1)
  .assignmentPolicy(RoleAssignmentPolicy.REPLACE_EXISTING)
  .build();

const pro = Role.builder('plan_pro').group(plan).permission('app.use').permission('app.plan.pro').build();
const max5 = Role.builder('plan_max5').group(plan).permission('app.use').permission('app.plan.max5').build();

const assignments = Pernorama.create().newRoleAssignments<string>();

assignments.assign('alice', pro).status;           // 'ASSIGNED'
const result = assignments.assign('alice', max5);
result.status;            // 'REPLACED'
result.previousRole?.id;  // 'plan_pro'

const alice = assignments.subject('alice');
alice.hasPermission('app.plan.max5'); // true
alice.hasPermission('app.plan.pro');  // false
```

**Cardinality.** When an assignment would take a target over a group's
`maxAssignments`, the group's policy decides: `REJECT` (the default),
`REPLACE_EXISTING`, `REPLACE_OLDEST` or `REPLACE_NEWEST`. Removing a role
that would take the target under `minAssignments` is rejected. Limits
are counted per context, with roles held without a context counted as
one more context.

**Roles in a context.** `assignments.assign('alice', teacher, 'academy:123')`
holds the role in that context only. Where it applies follows the
`ContextPolicy`, exactly as for a grant.

**Combining roles.** `assignments.subject(target, policy)` takes a
`PermissionResolutionPolicy`:

- `ALLOW_OVERRIDES` (default) — permitted if any role permits. A deny
  rule only limits the role that holds it.
- `DENY_OVERRIDES` — a role that explicitly denies the node vetoes the
  others.

Both are **context first**: under `GLOBAL_FALLBACK`, roles held in the
checked context decide before roles held without one, in either
direction.

**Roles plus direct grants.** `CompositePermissionSubject` answers from
several subjects, permitting what *any* of them permits. A deny rule in
one source does not veto another source:

```ts
import { CompositePermissionSubject } from '@noahsoft/pernorama';

const user = new CompositePermissionSubject(ownGrants, assignments.subject('alice'));
```

### Role assignments in a database

`RoleAssignments` is synchronous and needs a synchronous
`RoleAssignmentStore`. For a store that does I/O, implement
`AsyncRoleAssignmentStore` and use `AsyncRoleAssignments`: the same
rules and results, with every operation returning a promise.

```ts
const assignments = pernorama.newAsyncRoleAssignments(new PostgresRoleStore(pool));

await assignments.assign(userId, teacher, 'academy:123');

const subject = await assignments.subject(userId); // loads once
subject.hasPermission('students.read', 'academy:123'); // synchronous
```

A store is two methods: read a target's assignments, oldest first, and
**compare-and-set** them. Every change — including a replacement, which
removes one role and adds another — is one `replace` call, and is
retried from a fresh read when `replace` reports that the assignments
changed in between. A group's limits therefore hold under concurrency
*if `replace` compares and writes atomically in the database*:

```ts
class PostgresRoleStore implements AsyncRoleAssignmentStore<string> {
  async assignments(userId: string): Promise<readonly RoleAssignment[]> {
    // SELECT role_id, context FROM role_assignment WHERE user_id = $1 ORDER BY position
  }

  async replace(userId: string, expected: readonly RoleAssignment[], updated: readonly RoleAssignment[]): Promise<boolean> {
    // In ONE transaction:
    //   lock the user's rows (SELECT ... FOR UPDATE) or check a version column,
    //   return false if what is stored no longer equals `expected`,
    //   otherwise write `updated` and return true.
  }
}
```

Reading in one round trip and writing in the next without such a guard
is not a compare-and-set, and lets two concurrent assignments both go
over a maximum. The subject returned by `AsyncRoleAssignments.subject`
is a snapshot: load one per request rather than keeping it.

## Explaining a decision

`explain` answers *why*. Its `allowed` is always what `hasPermission`
returns for the same arguments.

```ts
const user = pernorama.newSubject(['students.delete']);
user.grant('-students.*', 'academy:123');

const why = user.explain('students.delete', 'academy:123');

why.allowed;       // false
why.decision;      // 'DENIED' ('NOT_COVERED' when no rule covers the node)
why.decidingLayer; // 'EXACT_CONTEXT'
why.provenance;    // 'COMPLETE'
why.matches.map(String); // ['-students.* @ academy:123 (decisive)', 'students.delete']
```

For a composite or a role-assignment subject, `contributions` lists each
source or `RoleAssignment` with its own explanation and whether it
decided, and `resolutionPolicy` names how they were combined.
`provenance` is `COMPLETE`, `PARTIAL` or `UNAVAILABLE`: a reason that
could not be determined is never reported. `Permission.explain(subject, node, context)`
works for any subject, including one that does not implement `explain`.

An explanation describes how a subject's permissions are configured.
Log it or show it to administrators; do not return it to the user whose
request was denied.

## Decorators

`@Perm` and `@PermGroup` are standard (TC39) decorators. They are not
exported directly: you create them, bound to **your** way of finding the
subject of a call. There is no global "current user".

```ts
// auth.ts
import { createPermissionDecorators } from '@noahsoft/pernorama';

export const { Perm, PermGroup } = createPermissionDecorators({
  subject: ({ args }) => (args[0] as Actor | undefined)?.permissions,
});
```

```ts
// user-service.ts
import { Perm, PermGroup } from './auth.js';

@PermGroup('users')
class UserService {
  @Perm('create')
  create(actor: Actor, name: string): User {
    // runs only if actor.permissions has users.create
  }
}
```

A call to a guarded method:

1. resolves the subject, then the context, in that order;
2. calls `subject.hasPermission(node, context)`;
3. only then runs the method body, with the same `this` and arguments.

### It fails closed

| Situation | Result | Body runs? |
| --- | --- | --- |
| The subject has the permission | the method's own result | yes |
| The subject lacks it | `PermissionDeniedException` | no |
| The resolver returned no subject, or not a subject | `AuthorizationUnavailableException` (`SUBJECT_UNAVAILABLE`) | no |
| A resolver threw | `AuthorizationUnavailableException` (`…_RESOLVER_FAILED`, the error as `cause`) | no |
| The context resolver returned `undefined`, `''` or a non-string | `AuthorizationUnavailableException` (`CONTEXT_UNAVAILABLE`) | no |
| `hasPermission` threw | that error | no |
| `hasPermission` returned a promise or any non-boolean | `IllegalStateError` | no |

`AuthorizationUnavailableException` is separate from a denial on
purpose: nobody was denied, the question could not be asked. An HTTP
layer usually maps it to 401 and `PermissionDeniedException` to 403.

### Contexts

Without a context resolver, guarded methods are checked without a
context. With one, each call is checked in the context it returns:

```ts
export const { Perm, PermGroup } = createPermissionDecorators({
  subject: ({ args }) => (args[0] as Request).actor.permissions,
  context: ({ args }) => {
    const academyId = (args[0] as Request).academyId;
    return academyId === undefined ? undefined : `academy:${academyId}`;
  },
});
```

A context resolver returns a non-empty string, or **`null` to check
without a context, explicitly**. Returning `undefined` means "unknown"
and fails the call: silently falling back to a check without a context
could permit exactly what a contextual deny rule forbids.

A method can override either resolver, or switch the context off:

```ts
@Perm('export', { context: null })                 // always checked without a context
@Perm('sweep', { subject: () => systemSubject })   // a different subject for this method
```

A resolver receives `{ permission, target, args, methodName, isStatic }`,
where `target` is `this` of the call.

### Asynchronous resolvers

`createPermissionDecorators` takes synchronous resolvers, so a guarded
method keeps its return type and timing. A denial is thrown
synchronously — except from a native `async` method, where it is a
rejection of the promise the method returns.

When resolving has to wait — loading the subject from a database — use
`createAsyncPermissionDecorators`:

```ts
export const { Perm, PermGroup } = createAsyncPermissionDecorators({
  subject: async ({ args }) => StoredSubject.load(db, (args[0] as Request).userId, pernorama.contextPolicy),
});
```

A method guarded this way always returns a promise and every failure is
a rejection. Its type only accepts methods that already return a
promise, so the guard never changes what a caller sees. The check itself
stays synchronous: resolve to a loaded subject.

### Inheritance, overriding and composition

These follow Java's rule, that a method-level `@Perm` belongs to the
method that declares it:

- A method **inherited without being overridden** stays guarded, with
  the node of the class that declared it. A subclass's own `@PermGroup`
  does not rename it.
- **An override does not inherit `@Perm`.** An overriding method without
  its own `@Perm` is not guarded. If it calls `super.method(...)`, that
  call goes through the inherited guard. Redeclare `@Perm` on an
  override that should require a permission.
- `@PermGroup` applies to the `@Perm` methods **declared in that class**,
  static and `#private` ones included. It is not inherited.
- A method takes **one** `@Perm`; a second is an error when the class is
  defined. Check further permissions in the body with
  `Permission.require`.
- Decorators run outermost first. Put `@Perm` **above** other method
  decorators so that nothing else runs for an unauthorized call. If
  another decorator is above it, that decorator's code runs first; the
  body is still guarded.
- On a class, `@Perm('admin')` only declares a node for the registry. It
  guards nothing, and neither decorator guards a constructor.
- Invalid values fail when the class is defined, not on the first call:
  `@Perm('users.*')` throws `InvalidPermissionException`.

### Inspecting what was declared

```ts
import { PermissionAnnotationResolver, PermissionRegistry } from '@noahsoft/pernorama';

PermissionAnnotationResolver.resolve(UserService.prototype.create); // 'users.create'

const registry = new PermissionRegistry();
registry.register(UserService);         // reads @Perm/@PermGroup declared on this class
registry.registerNode('billing.refund'); // a node that is only checked directly
registry.all().map(String);             // ['users.create', 'billing.refund']
registry.validate('users.create');      // true
```

There is no classpath to scan in JavaScript: only classes you pass to
`register` are read, and only what was declared with decorators made by
this package.

### Security limitations

Decorators make it hard to *forget* a check on a method. They are not a
security boundary around your process. Know what they do not cover:

- **Only calls that reach the decorated method are guarded.** That
  includes `instance.method()`, a detached reference to it, and
  `super.method()`. It does not include: an override that does not
  redeclare `@Perm`; a reference to the undecorated implementation kept
  by another decorator placed *below* `@Perm`; code that replaces the
  method at runtime (`Service.prototype.create = ...`); and every other
  way of doing the same work — another method, a plain function, a
  queue consumer, a direct database call. Decorators exist only on class
  members; guard free functions with `Permission.require`.
- **The subject resolver is the trust boundary.** A guarded method
  authorizes whoever the resolver returns. If the subject is taken from
  an argument, code that can pass any argument can pass a subject that
  permits everything. Resolve the subject from something the caller
  cannot forge — an authenticated request object your framework built —
  and do not expose guarded services to untrusted in-process code.
- **Pernorama does not authenticate.** It answers "may this subject do
  X", never "who is this".
- **Contexts are not verified.** `academy:123` is whatever your resolver
  returned; Pernorama does not check that it exists or that the caller
  belongs to it.
- **The check happens once, when the method is called.** Permissions
  revoked while an `async` method or a generator is still running do not
  stop it, and a subject loaded for a request is a snapshot.
- **Getters, setters, fields and constructors cannot be guarded**, and
  `@Perm` refuses to decorate them rather than appear to.
- **Legacy decorators are not supported.** With `experimentalDecorators`
  the decorators throw when the class is defined, instead of guarding
  with the wrong permission. No reflection metadata
  (`emitDecoratorMetadata`, `reflect-metadata`) is used.
- **`Symbol.metadata`.** Creating decorators defines `Symbol.metadata`
  if the runtime has not (as `Symbol.for('Symbol.metadata')`), because
  compilers only emit decorator metadata when it exists. Create the
  decorators before the classes that use them are defined — importing
  them from a module does that. A build that provides no metadata fails
  at class definition.
- Tested with TypeScript's own decorator emit. Other compilers'
  implementations of standard decorators are expected to work but are
  not part of the test suite.

### Difference from Java

In Java, `@Perm` is **metadata only**. Nothing enforces it unless you
call through `PermissionInterceptor.invoke(subject, target, method, args)`,
which is opt-in: a direct `service.createUser()` is not intercepted, the
subject is passed in by the caller, and the check has no context.

In TypeScript there is no reflective proxy to opt into, so `@Perm`
**wraps the method**: every call through the class is checked, the
subject comes from the strategy you configured, and a context can be
resolved per call. The resolution rule — one node per method, combined
with the declaring class's `@PermGroup`, not inherited by overrides — is
the same. There is no `PermissionInterceptor` class in this package;
calling `Permission.require` yourself is the explicit equivalent.

## Compatibility with Java

The authorization rules are a port of the Java implementation, which is
the reference. `spec/*.json` holds the cases both test suites run:

| Fixture | Covers |
| --- | --- |
| `permission-cases.json` | node and rule syntax, wildcard matching, deny precedence and ties, malformed input |
| `context-cases.json` | context validity, `EXACT` and `GLOBAL_FALLBACK`, context-before-global precedence, contextless checks, revoke |
| `role-cases.json` | composite subjects, role and group ids, cardinality and replacement policies, per-context limits, `ALLOW_OVERRIDES`/`DENY_OVERRIDES`, context-first resolution, explanations with source attribution and provenance |

Java (`ConformanceTest`) and TypeScript (`test/conformance`) read the
same files; see [`spec/README.md`](../spec/README.md). No semantic
difference between the two implementations is known in what the
fixtures cover.

| Java | TypeScript |
| --- | --- |
| `PermissionNode`, `PermissionResolver`, `PermissionGrant`, `ContextPolicy`, `Permission`, `PermissionExplanation` | same names |
| `PermissionResolver.Decision`, `PermissionExplanation.Layer` / `Provenance` / `RuleMatch` / `Contribution` | top-level `Decision`, `Layer`, `Provenance`, `RuleMatch`, `Contribution`; the enums are string constants |
| `PermissionSubject`, `MemoryPermissionSubject`, `CompositePermissionSubject` | same names |
| `Role`, `RoleGroup`, `RoleAssignment`, `RoleAssignments`, `RoleAssignmentStore`, `MemoryRoleAssignmentStore`, `RoleAssignmentPolicy`, `RoleAssignmentDecision`, `RoleAssignmentResult`, `RoleAssignmentStatus`, `PermissionResolutionPolicy` | same names |
| `Pernorama.builder()` | same, plus `Pernorama.create({ contextPolicy })` |
| `PermissionDeniedException`, `InvalidPermissionException`, `PernoramaException` | same names |
| `IllegalArgumentException` / `NullPointerException`, `IllegalStateException`, `UnsupportedOperationException` | `IllegalArgumentError`, `IllegalStateError`, `UnsupportedOperationError` |
| `Optional<T>` | `T \| null` |
| accessor methods (`explanation.allowed()`) | readonly properties (`explanation.allowed`); `parent()`, `grants()` and operations stay methods |
| `@Perm`, `@PermGroup`, `PermissionAnnotationResolver`, `PermissionRegistry` | decorators from `createPermissionDecorators`; same resolver and registry names |

Differences to be aware of:

- **Checks are synchronous in both.** TypeScript adds
  `AsyncRoleAssignmentStore` / `AsyncRoleAssignments` and
  `createAsyncPermissionDecorators` for what has to wait on I/O; Java
  has no counterpart because its stores block.
- **`explain` is optional** on the `PermissionSubject` interface, where
  Java has a default method. `Permission.explain` supplies the default.
- **Equality is explicit.** `Role`, `RoleGroup`, `RoleAssignment`,
  `PermissionGrant` and `PermissionNode` have `equals` methods; `===`
  compares instances. `MemoryRoleAssignmentStore` looks targets up as
  `Map` keys, so identify targets by a primitive such as a user id.
- **Runtime type checks.** A value that is not a string is an invalid
  node, rule or context, and a non-boolean answer from a subject or
  policy is an error. Java's compiler rules these out.
- **A missing argument** is `IllegalArgumentError`, where Java throws
  `NullPointerException`.
- **`MemoryPermissionSubject.grants()`** returns a snapshot in grant
  order, not a live unordered view.
- **`AuthorizationUnavailableException`** exists only here, for guarded
  methods.
- Role and group ids are validated with Java's definition of whitespace,
  not `String.prototype.trim`'s, so the same id is valid in both.

Not ported:

- **`PermissionInterceptor`** — see [Difference from Java](#difference-from-java).
- **Classpath-style scanning** in `PermissionRegistry`.
- **Thread-safety guarantees**, which have no meaning on one thread; see
  [Role assignments in a database](#role-assignments-in-a-database) for
  what replaces them across `await`.
- The `checkPathBenchmark` timing harness.

Not planned: authentication, ABAC conditions, context hierarchies or
wildcard contexts, and framework, database, Discord or JWT adapters in
the core. Those are integrations to build on `PermissionSubject`.

## Errors

| Error | Extends | Thrown when |
| --- | --- | --- |
| `InvalidPermissionException` | `PernoramaException` | a node or rule is syntactically invalid |
| `PermissionDeniedException` | `PernoramaException` | `Permission.require` or a guarded method finds the permission missing |
| `AuthorizationUnavailableException` | `PernoramaException` | a guarded method could not resolve its subject or context |
| `IllegalArgumentError` | `Error` | an empty context, a blank id, contradictory group limits, a missing argument |
| `IllegalStateError` | `Error` | a policy or store broke its contract, a subject did not answer with a boolean, a decorator was misused |
| `UnsupportedOperationError` | `Error` | `grant`/`revoke` on a read-only subject |

A plain `hasPermission` on valid input never throws.

## Versioning

The package follows semantic versioning, independently of the Java
artifact: `@noahsoft/pernorama@0.1.0` and `io.pernorama:pernorama:0.3.0`
are unrelated numbers. Which Java behavior a release matches is recorded
in [CHANGELOG.md](CHANGELOG.md) and pinned by the fixtures it was tested
against (`specVersion` in `spec/*.json`).

While the version is `0.x`, the API documented here may still change in
a minor release; such a change is called out in the changelog. Only what
is exported from the package root is public API — there are no
deep-import entry points.

## Releasing

Java and TypeScript release separately:

| | Tag | Workflow | Destination |
| --- | --- | --- | --- |
| Java | `v<version>` | `.github/workflows/publish.yml` | `maven.noahsoft.kr` |
| TypeScript | `ts-v<version>` | `.github/workflows/publish-npm.yml` | npm |

A `ts-v*` tag does not match `v*`, so one tag never triggers both.

To release the TypeScript package:

1. Set `version` in `typescript/package.json`, update
   `typescript/CHANGELOG.md`, and merge.
2. Run `npm run verify` in `typescript/`.
3. Tag the merge commit `ts-v<version>` and push the tag. The workflow
   checks that the tag matches `package.json`, runs `npm run verify`,
   and publishes.

**Publishing is not enabled yet.** The workflow only performs
`npm publish --dry-run` until both of these are done by a maintainer:

- **The package name is confirmed.** `@noahsoft/pernorama` is
  provisional. When this was written the name was unpublished and an
  npm organization named `noahsoft` existed, but whether NOAHSOFT
  controls it could not be verified from a development machine. Confirm
  with `npm org ls noahsoft` as a maintainer, or choose another scope
  and update `name` in `package.json`.
- **Trusted Publishing is configured.** The workflow authenticates with
  npm through OIDC and holds no token. On npmjs.com, add this repository
  and `publish-npm.yml` as a trusted publisher for the package, then set
  the repository variable `NPM_TRUSTED_PUBLISHING` to `true`. npm may
  require the package to exist before a trusted publisher can be
  attached; if so, the first version has to be published once by a
  maintainer.

Never add an npm token to the repository, to a workflow file, or to
`.npmrc`.

## Development

```bash
cd typescript
npm ci

npm run typecheck          # strict TypeScript, sources and tests
npm test                   # unit tests and the shared conformance fixtures
npm run test:conformance   # only the fixtures in ../spec
npm run build              # dist/: ES modules, declarations, source maps
npm run check:package      # what would be published, and that the build is reproducible
npm run smoke              # install the tarball into ESM, CommonJS and TypeScript consumers
npm run verify             # all of the above
```

Tests run on Node's built-in test runner against TypeScript's own
output; the only development dependencies are `typescript` and
`@types/node`.

A change to authorization behavior starts in the Java implementation and
in `spec/`: add the case to a fixture, see it pass in Java, then make
the TypeScript suite pass. A fixture that Java fails is a wrong fixture.

## License

[MIT](LICENSE).
