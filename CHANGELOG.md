# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Scoped permissions with contexts** ([#12](https://github.com/NOAHSOFTKR/pernorama/issues/12)).
  A grant and a check can name a context — an opaque,
  application-defined string such as `academy:123` — so one subject can
  hold a permission in one scope and not another:
  `grant("students.edit", "academy:123")`,
  `hasPermission("students.edit", "academy:123")`,
  `revoke("students.edit", "academy:123")`. Pernorama does not generate,
  parse, validate, or interpret context values; contexts match by string
  equality only, and `null` is the one spelling of "no context" (an
  empty string is rejected).
  - `Pernorama`, the application's configuration root:
    `Pernorama.builder().contextPolicy(...).build()`, with
    `newSubject()`, `newSubject(rules)` and `newRoleAssignments(...)`
    creating components that use its settings, and a
    `MemoryPermissionSubject(ContextPolicy, Collection)` constructor
    behind `newSubject(rules)`.
  - `ContextPolicy`, chosen once per `Pernorama` instance:
    `GLOBAL_FALLBACK` (the default; a grant without a context applies in
    every context, underneath that context's own grants) or `EXACT`
    (grants with and without a context are separate). Under
    `GLOBAL_FALLBACK` the grants in the checked context decide whenever
    any of their rules covers the node, and the global grants only
    otherwise. `ContextPolicy.permits(grants, node, context)` is the one
    implementation of this, for custom subjects too.
  - `PermissionGrant`, a rule plus a nullable context.
  - `PermissionResolver.decide(rules, node)`, the three-way answer
    behind `matchesAny` — `PERMITTED`, `DENIED` or `NOT_COVERED` — so
    "explicitly denied" and "not covered at all" can be told apart.
  - `Permission.check`/`require` overloads taking a context, and
    `PermissionDeniedException.context()`.
  - Role assignments in a context: `RoleAssignments.assign`/`unassign`/
    `roles` take a context, a `RoleAssignment` is a role plus a nullable
    context, group limits are counted per context, and
    `RoleAssignmentResult.context()` reports where a change happened.
    `roles(target)` lists only the roles held without a context;
    `assignments(target)` lists every one. Under `GLOBAL_FALLBACK` the
    built-in resolution policies put roles held in the checked context
    first, as grants are: if any of them permits or denies the node,
    they decide, and the roles held without a context only otherwise.
    A role built from rules carries no context, so its own
    `permissions()` answers a check in a context with `false`; a role
    backed by a subject answers as that subject does.

  A check without a context behaves exactly as before under either
  policy.
- **A role layer, `pernorama.role`,** for applications that need rules
  about which roles a target may hold, on top of the
  `PermissionSubject` core:
  - `Role` — a named bundle of permission rules (or a wrapper around an
    existing `PermissionSubject`), optionally in a group. Its permissions
    are evaluated by `PermissionResolver`; nothing is re-implemented.
  - `RoleGroup` — `minAssignments`/`maxAssignments` for related roles,
    and the `RoleAssignmentPolicy` applied when an assignment would go
    over the maximum: built-in `REJECT`, `REPLACE_EXISTING`,
    `REPLACE_OLDEST`, `REPLACE_NEWEST`, or your own returning a
    `RoleAssignmentDecision`. A group id has one definition: roles
    carrying same-id groups with different limits or policies are
    rejected with `IllegalStateException` instead of bypassing a limit.
  - `RoleAssignments` — `assign`/`unassign` returning a
    `RoleAssignmentResult` (`ASSIGNED`, `REPLACED`, `UNASSIGNED`,
    `NO_CHANGE`, `REJECTED`, plus the roles removed), with idempotent
    reassignment and replacement applied as one atomic write.
  - `RoleAssignmentStore`, a read plus compare-and-set contract over a
    target's `RoleAssignment`s for persistence adapters, and the
    in-memory `MemoryRoleAssignmentStore`.
  - `PermissionResolutionPolicy`, separate from the assignment policy,
    for combining the permissions of the held roles that apply to a
    check: `ALLOW_OVERRIDES` (without contexts, the
    `CompositePermissionSubject` behavior, and the default) and `DENY_OVERRIDES`, or your own.

  `CompositePermissionSubject` and every other existing type behave as
  before.

### Changed

- **Breaking for custom `PermissionSubject` implementations:** the
  methods to implement are now `hasPermission(String, String)`,
  `grant(String, String)` and `revoke(String, String)`, whose second
  argument is the context. The overloads without a context are default
  methods passing `null`, so callers are unaffected. To upgrade an
  implementation, add the context parameter to its three methods, and
  either store it — keeping `PermissionGrant`s and deciding with
  `pernorama.contextPolicy().permits(grants, node, context)` — or, for a
  subject that has no contexts, answer `false` to a check with one and
  reject a grant with one. Ignoring the context would let a contextual
  check pass on a global grant even under `EXACT`.
- **Breaking for subclasses of `MemoryPermissionSubject`:** its
  `hasPermission(String)`, `grant(String)` and `revoke(String)` are now
  `final`. Override the two-argument methods instead: callers that pass
  a context — `CompositePermissionSubject`, `Permission.check(subject,
  node, context)` — call those directly,
  so an override of a one-argument method would be silently skipped
  for them. The compile error makes that visible.
- **Breaking: `MemoryPermissionSubject.grantedPermissions()` is replaced
  by `grants()`,** a read-only live view of `PermissionGrant`s, because a
  rule string alone no longer says which context it was granted in. The
  old result is
  `grants().stream().filter(g -> !g.hasContext()).map(PermissionGrant::rule)`.
- **`PermissionAnnotationResolver`'s cache no longer keeps classes
  alive.** Resolution results used to live in a static, unbounded
  `ConcurrentHashMap` keyed by `Method`, and a `Method` pins its
  declaring class — and therefore that class's `ClassLoader`. Classes
  generated at runtime and then discarded, which is what a CGLIB or
  dynamic-proxy integration produces per target, accumulated there for
  the lifetime of the JVM. The cache now hangs off the declaring class
  itself, through `ClassValue`, so its entries become unreachable
  together with the class that owns them. Resolved values, thread
  safety and the public API are unchanged; nothing to do on upgrade.

## [0.2.0-beta.2] - 2026-09-21

### Added

- **Deny rules.** A rule prefixed with `-` denies instead of allows, so a
  broad grant can have exceptions carved out of it:
  `grant("users.*")` plus `grant("-users.delete")` permits everything
  under `users` except `users.delete`. The most specific rule covering a
  node decides — an exact rule beats a wildcard one, a longer wildcard
  prefix beats a shorter one — and a deny rule wins a tie, so
  `["-users.*", "users.read"]` permits exactly `users.read` under
  `users`.
- `PermissionResolver.denies(pattern, node)`, the mirror of
  `matches(pattern, node)`, for testing a single deny rule.
- `CompositePermissionSubject`, a read-only `PermissionSubject` that
  answers from several other subjects at once — the "a user holds roles,
  and each role carries permissions" shape. `hasPermission` is true if
  any source says so, and a deny rule only limits the source holding it;
  `grant`/`revoke` throw `UnsupportedOperationException`, since the
  composite has no storage of its own.
- `ROADMAP.md`, describing the hardening planned before 1.0, what 1.0
  commits to, and the API questions that had to be answered before the
  API freezes.

### Changed

- **`PermissionResolver.matchesAny` now applies deny rules and
  specificity** rather than returning `true` at the first rule that
  covers the node, and no longer stops at the first match: every rule is
  examined so the most specific one can be found. A rule set containing
  no deny rules gives the same answer as before, with one exception —
  because every rule is now validated, a malformed rule that used to sit
  unreached behind a matching one (`["*", "users..bad"]`) now throws
  `InvalidPermissionException` on every check. Subjects that validate on
  `grant`, `MemoryPermissionSubject` among them, cannot hold such a rule
  in the first place.
- **`PermissionResolver.matches`, `denies` and `matchesAny` now validate
  the required node**, not just the rules, and throw
  `InvalidPermissionException` for a value that is not one. Without this
  a caller could ask about `-users.read` or `users.*` and get an answer
  that stepped around a deny rule; a custom subject that passes its
  argument straight through now reports an invalid node the way
  `PermissionSubject` says it should.
- **`PermissionResolver.matches` now returns `false` for a deny rule.**
  It answers "does this rule *allow* the node", so `-users.delete` no
  longer reads as an ordinary node that happens to start with a hyphen.
- **A permission node may no longer start with `-`.**
  `PermissionNode.of("-users")` and `PermissionNode.isValid("-users")`
  now reject it, and `hasPermission("-users")` throws with them, because
  a leading `-` marks a deny rule. The character stays legal everywhere
  else in a segment, so `users.soft-delete` is unaffected.
- **A stored grant that begins with `-` changes meaning.** It used to be
  an inert grant of an oddly-named node; it is now an active deny that
  can remove access a wildcard grant would otherwise give. Nothing
  rejected such strings before, so check existing stored permissions for
  a leading `-` before upgrading.
- The self-hosted Reposilite repository is now referred to by its canonical
  host, `maven.noahsoft.kr`, in the install instructions and the publishing
  configuration. `maven.kjh9211.kr` is an alias for the same instance and keeps
  working, so already-published versions do not need to be re-fetched.

## [0.2.0-beta.1] - 2026-09-04

First Beta release. The public API documented in `README.md` is intended to be
the shape 1.0 ships with; see [API Stability](README.md#api-stability).

### Added

- `Permission.check(subject, node)` / `Permission.require(subject, node)` for
  checking permissions from plain Java code, without annotations or reflection.
- `PermissionAnnotationResolver`, a single cached implementation of the
  `@Perm`/`@PermGroup` resolution rule, shared by `PermissionInterceptor` and
  `PermissionRegistry`.
- A `PernoramaException` base type, and `InvalidPermissionException` (carrying
  the offending value) for values that are not valid permission nodes or
  patterns.
- `PermissionRegistry.validate(node)`, which checks both node syntax and
  registration.
- MIT `LICENSE`, plus license and SCM metadata in the published POM.
- `CHANGELOG.md`.
- A `CI` workflow running the test suite on pushes to `main` and on pull
  requests.

### Changed

- Permission validation and wildcard matching are centralized in
  `PermissionResolver`; `PermissionNode` delegates to it instead of duplicating
  the segment pattern.
- `MemoryPermissionSubject` is now thread-safe, backed by a `ConcurrentHashMap`
  key set.
- **`MemoryPermissionSubject.grantedPermissions()` no longer has a defined
  iteration order.** It previously returned a `LinkedHashSet` documented as
  being in grant order; the switch to a `ConcurrentHashMap` key set drops that
  guarantee. Sort the result if you depend on a stable order.
- `PermissionDeniedException` now extends `PernoramaException` instead of
  `RuntimeException`. Its constructor and accessors are unchanged, so
  `catch (PermissionDeniedException e)` keeps working.
- Invalid permission values now throw `InvalidPermissionException` instead of
  `IllegalArgumentException`.
- The published POM `url` points at `NOAHSOFTKR/pernorama`.
- `README.md` was rewritten for Beta users, and every code sample in it is
  compiled and asserted by `ReadmeExamplesTest`.
- The annotation resolution rule is now documented and pinned by tests: an
  overriding method does not inherit `@Perm` (or the declaring type's
  `@PermGroup`), matching plain Java annotation semantics, while inherited and
  interface default methods resolve through their true declaring class.
- Thread-safety is documented per public type, including that
  `PermissionRegistry` is not thread-safe and is meant to be populated once at
  startup.

## [0.1.0] - 2026-09-01

### Added

- Initial MVP: `PermissionNode`, `PermissionResolver`, `PermissionSubject`,
  `MemoryPermissionSubject`, `PermissionRegistry`, `PermissionInterceptor`,
  `PermissionDeniedException`, and the `@Perm` / `@PermGroup` annotations.
- Maven/Gradle publishing to the self-hosted Reposilite repository at
  `maven.noahsoft.kr`, with sources and javadoc jars and a tag-triggered publish
  workflow.

[Unreleased]: https://github.com/NOAHSOFTKR/pernorama/compare/v0.2.0-beta.2...HEAD
[0.2.0-beta.2]: https://github.com/NOAHSOFTKR/pernorama/compare/v0.2.0-beta.1...v0.2.0-beta.2
[0.2.0-beta.1]: https://github.com/NOAHSOFTKR/pernorama/releases/tag/v0.2.0-beta.1
[0.1.0]: https://github.com/NOAHSOFTKR/pernorama/commit/ccd6e69734c4b82c74a905d53afbd46422afe97d
