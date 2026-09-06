# Roadmap

This file describes where Pernorama is headed after
`0.2.0-beta.1`. It is a statement of intent, not a schedule: there
are no dates here, ordering may change, and an item may be dropped
if it turns out not to earn its place. Whatever actually ships is
recorded in [CHANGELOG.md](CHANGELOG.md).

Anything that shapes the public API has to be settled before 1.0
freezes it. What has been decided so far is recorded under **Settled**
below; everything after it is still open work.

## Where we are today

`0.2.0-beta.1` is the current release, and the core is complete:

- `PermissionNode` — parsing and structure of a dotted node.
- `PermissionResolver` — the single definition of valid syntax and of
  wildcard matching (`*`, `users.*`).
- `PermissionSubject` / `MemoryPermissionSubject` — the
  storage-agnostic interface and its thread-safe in-memory
  implementation.
- `@Perm` / `@PermGroup` and `PermissionAnnotationResolver` — one
  cached implementation of the annotation resolution rule.
- `PermissionInterceptor`, `Permission`, `PermissionRegistry`.
- `PernoramaException`, `InvalidPermissionException`,
  `PermissionDeniedException`.

[README.md](README.md) documents all of this except the
`PernoramaException` base type, which is described only in its own
javadoc.

The library depends on the JDK only, targets Java 21+, is tested on
pushes to `main` and on pull requests, and is published to
`maven.noahsoft.kr` from a `v*` tag.

## Principles

Every item below is judged against these; an item that violates one
is a non-goal, not a backlog entry.

1. **The core depends on the JDK only.** Integrations
   (Spring, Discord, JWT, a database) live in separate, optional
   modules built on `PermissionSubject`.
2. **One rule lives in one place.** Syntax and wildcard matching
   belong to `PermissionResolver`; annotation resolution belongs to
   `PermissionAnnotationResolver`. A second implementation of either
   is a bug.
3. **Documented behavior is pinned by tests.** Every runnable README
   example is compiled and asserted by `ReadmeExamplesTest`; anything
   the README promises should be enforceable the same way.
4. **Behavior changes are announced, not silent.** Beta may still
   change the API shape, but only with a `CHANGELOG.md` entry that
   says what to do about it.
5. **A small API surface is a feature.** Prefer documenting a recipe
   over adding a type.

## Before 1.0 (`0.2.0-beta.x`)

The work between here and 1.0 is hardening: closing the decisions the
API cannot change later, and paying off the limitations the current
code already documents.

### Settled

- **Deny rules.** A rule prefixed with `-` denies instead of allows, and
  the most specific rule covering a node decides, with a deny winning a
  tie. This replaced the additive-only model, in which `revoke` could
  not narrow a wildcard grant.
- **Roles and composition.** `CompositePermissionSubject` answers from
  several subjects at once. It is read-only, and a deny rule limits only
  the source that holds it.

Both are documented in [README.md](README.md) and recorded in
[CHANGELOG.md](CHANGELOG.md). What is left:

### 1. The annotation cache lifetime

`PermissionAnnotationResolver` caches resolution per `Method` in a
static, unbounded map. A `Method` pins its declaring `Class`, and
therefore its `ClassLoader`, so classes generated at runtime and
discarded — exactly what a CGLIB or dynamic-proxy integration
produces — accumulate forever. The class javadoc already calls this
out and says to revisit it before shipping a framework integration.

Direction: make the cache bounded or weakly keyed. Moving it to a
per-resolver instance would work too, but `PermissionAnnotationResolver`
is a static utility class today, so that variant is an API change and
not a drop-in fix. This blocks the proxy-based modules below, so it
lands before them.

*Done when* a test demonstrates that a discarded generated class does
not stay reachable through the cache.

### 2. Check-path cost

`MemoryPermissionSubject.hasPermission` builds a `PermissionNode`
(splitting the string into segments and joining them back) and then
`PermissionResolver.matchesAny` scans the rules linearly, re-validating
each one with a regex. Since deny rules landed it can no longer stop at
the first match — it has to see every rule to find the most specific
one — so every check now costs a full pass. That is irrelevant for a
subject with a handful of rules and measurable for one with hundreds on
a request path.

Direction: measure before changing anything. Add a benchmark (a JMH
source set, or a plain harness — either way, without adding a runtime
dependency to the core), then consider skipping the node round-trip on
the `String` overload and dropping the re-validation inside `matches`
— `MemoryPermissionSubject` already validates in `grant`/`revoke`, but
`matches` is public and documented to throw on a bad pattern, so that
one is a contract decision, not just an optimization. An indexed
structure only if the numbers justify one.

*Done when* a repeatable benchmark lives in the repository and any
optimization leaves the existing semantics tests green.

### 3. `PermissionInterceptor` method lookup

`invoke(subject, target, methodName, args...)` selects a method by
name and argument *count* among public methods, and rejects an
ambiguous match by pointing at the `Method` overload. It then calls
`setAccessible(true)`, which can fail for a type in a module that
does not open its package.

Direction: state the lookup rule in the README (it is currently only in
`PermissionInterceptor`'s javadoc), consider an overload that
takes explicit parameter types, and decide what the module-path story
is — most likely documenting that the target's package must be open,
rather than dropping `setAccessible`.

### 4. Registry sharpening

`PermissionRegistry` is deliberately not thread-safe and is meant to
be populated once at startup. Two follow-ups:

- An explicit frozen view, so a late `register` is a clear error
  instead of a race.
- Whether classpath or package scanning belongs in Pernorama at all.
  In the core it would mean either a new dependency or hand-rolled
  classloader walking, both of which fight principle 1 — so the
  likely answer is that `register(Class)` stays in the core and
  scanning belongs to an integration module.

The README should also state what the class javadoc already does:
`register` looks at methods declared directly on the scanned class,
so an inherited annotated method is not registered by scanning the
subclass.

## 1.0.0

1.0 is a promise, so it is defined by what stops changing rather than
by a feature list. It ships when the items above are done and:

- **The documented API is frozen** under semantic versioning, with a
  mechanical guard in CI (`japicmp` or Revapi) so an accidental
  breaking change fails the build instead of surfacing downstream.
- **The jar declares a module identity** — at minimum an
  `Automatic-Module-Name` manifest attribute, preferably a real
  `module-info` for the core.
- **Distribution is settled.** Either 1.0 is also published to Maven
  Central — which needs `io.pernorama` namespace verification, signed
  artifacts and a Central Portal account — or the README says plainly
  that `maven.noahsoft.kr` is the only channel, so nobody waits for a
  coordinate that is not coming.
- **CI covers more than one JDK**, so a break on a newer release is
  caught before a user reports it.

## After 1.0 — optional modules

The README already names Spring Security, Discord, JWT, OAuth2, a SQL
database and Redis as out of scope for Beta, and says they are meant to
live in separate, optional modules built on `PermissionSubject`. That
is still where they belong after 1.0: each is a separate artifact so
the core keeps its "JDK only" guarantee, which means the build splits
into modules and probably gains a BOM. Splitting also decides what the
core artifact is called — keeping `io.pernorama:pernorama` for it
avoids breaking the coordinate every existing user depends on. Any
module that proxies annotated methods depends on the cache work in
item 1.

- **Spring** — enforcing `@Perm` through AOP, plus a starter.
- **Discord** — a `PermissionSubject` backed by a member's roles.
- **JWT** — a `PermissionSubject` backed by a claim.
- **Persistence adapters** — a subject backed by a table or a cache.
- **Documentation generation** — turning a populated
  `PermissionRegistry` into Markdown or JSON. The README already lists
  generating documentation as a reason the registry exists; actually
  shipping a generator does not have to happen in the core.

## Non-goals

- **Authentication.** Pernorama answers "may this subject do X", not
  "who is this subject".
- **Wildcards anywhere but the last segment.** `users.*.read` stays
  invalid; the trailing-only rule is what keeps matching predictable.
- **A general policy engine.** Conditions, attributes and rule
  ordering (ABAC) are a different library.
- **Dependencies in the core**, including for scanning, logging or
  JSON.

## Changing this roadmap

Open an issue on
[NOAHSOFTKR/pernorama](https://github.com/NOAHSOFTKR/pernorama/issues)
— a concrete use case is worth more than a preference, especially for
anything that would change a decision already listed as settled.
Anything that ships moves from here into
[CHANGELOG.md](CHANGELOG.md).
