# Roadmap

This file describes where Pernorama is headed after
`0.2.0-beta.1`. It is a statement of intent, not a schedule: there
are no dates here, ordering may change, and an item may be dropped
if it turns out not to earn its place. Whatever actually ships is
recorded in [CHANGELOG.md](CHANGELOG.md).

Items marked **Open question** are decisions that have not been made
yet. They are listed here because they shape the public API, so they
need an answer *before* 1.0 rather than after.

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

### 1. Deny rules — Open question

Grants are purely additive today. `revoke` removes an exact string
previously granted, so it cannot narrow a broader wildcard: after
`grant("users.*")`, revoking `users.delete` does nothing. That is
documented in `PermissionSubject`'s javadoc and pinned by a test, but
it is not in the README, and it is still a real gap: there is no way
to express "everything under `users`, except `users.delete`".

The decision is whether to support negation — a `-users.delete`
prefix form, or a separate deny set on the subject — or to declare it
out of scope. It cannot be deferred past 1.0: it changes the
`PermissionResolver.matches` contract and therefore every custom
`PermissionSubject` that reuses it. Note that a `-` prefix is not
free either: `-` is a legal character inside a segment today, so
`-users.delete` is currently a valid node, and giving it a second
meaning would be a breaking change to the syntax.

*Done when* either the semantics ship with precedence rules
(deny-wins vs. most-specific-wins) documented and tested, or the
README names negation as a non-goal and points at the workaround
(grant the narrower nodes explicitly).

### 2. Roles and composition — Open question

"A subject holds roles; roles carry permissions" is the shape most
applications need, and today every application re-implements it
inside its own `PermissionSubject`. The options are to ship a
composing subject in the core (one that delegates to an ordered list
of other subjects) or to leave it to implementers and document the
recipe in the README next to
[Custom PermissionSubject](README.md#custom-permissionsubject).

*Done when* the README either documents a shipped composition type or
shows the recipe as an example that `ReadmeExamplesTest` compiles.

### 3. The annotation cache lifetime

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

### 4. Check-path cost

`MemoryPermissionSubject.hasPermission` builds a `PermissionNode`
(splitting the string into segments and joining them back) and then
`PermissionResolver.matchesAny` scans grants linearly, re-validating
each pattern it examines with a regex. It stops at the first match, so
a denied check is the expensive one — it walks every grant. That is
irrelevant for a subject with a handful of grants and measurable for
one with hundreds on a request path.

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

### 5. `PermissionInterceptor` method lookup

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

### 6. Registry sharpening

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
by a feature list. It ships when the open questions above are
answered and:

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
item 3.

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
— particularly for the **Open question** items, where a concrete use
case is worth more than a preference. Anything that ships moves from
here into [CHANGELOG.md](CHANGELOG.md).
