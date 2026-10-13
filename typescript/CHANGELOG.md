# Changelog

All notable changes to the TypeScript package, `@noahsoft/pernorama`,
are documented in this file. The Java artifact has its own changelog,
[`../CHANGELOG.md`](../CHANGELOG.md), and its own version numbers.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

The first version of the TypeScript SDK
([#18](https://github.com/NOAHSOFTKR/pernorama/issues/18)). Nothing has
been published to npm yet.

It ports the Java implementation as of its unreleased `explain` work
(Java `0.3.0` plus `PermissionExplanation`), and is tested against the
same fixtures, `spec/*.json` at `specVersion` 1.

- **Core.** `PermissionNode`, `PermissionResolver`, `PermissionGrant`,
  `ContextPolicy` (`GLOBAL_FALLBACK`, `EXACT`), `Permission.check` /
  `require` / `explain`, `PermissionSubject`, `MemoryPermissionSubject`,
  `CompositePermissionSubject`, and `Pernorama` as the factory that
  carries the context policy.
- **Explanations.** `PermissionExplanation` with the three-way
  `decision`, the `decidingLayer`, `matches`, per-source `contributions`
  and `provenance`.
- **Roles.** `Role`, `RoleGroup`, `RoleAssignments`, `RoleAssignment`,
  `RoleAssignmentStore` and `MemoryRoleAssignmentStore`, the
  `RoleAssignmentPolicy` constants (`REJECT`, `REPLACE_EXISTING`,
  `REPLACE_OLDEST`, `REPLACE_NEWEST`) and `PermissionResolutionPolicy`
  (`ALLOW_OVERRIDES`, `DENY_OVERRIDES`).
- **Asynchronous role stores.** `AsyncRoleAssignmentStore` and
  `AsyncRoleAssignments`, for stores that do I/O. Not in Java.
- **Decorators.** `createPermissionDecorators` and
  `createAsyncPermissionDecorators` return `@Perm` and `@PermGroup`
  standard (TC39) decorators bound to an explicit subject — and
  optionally context — resolver. Guarded methods fail closed;
  `AuthorizationUnavailableException` reports authorization that could
  not be evaluated. `PermissionAnnotationResolver` and
  `PermissionRegistry` read what was declared.
- **Errors.** `PernoramaException`, `InvalidPermissionException`,
  `PermissionDeniedException`, and `IllegalArgumentError`,
  `IllegalStateError`, `UnsupportedOperationError` for Java's
  corresponding runtime exceptions.

### Notes

- ES modules only, with type declarations and source maps; CommonJS code
  loads it with `require` on Node.js 22.12 or later. No runtime
  dependencies.
- Java's `PermissionInterceptor` is not ported; see "Difference from
  Java" in the [README](README.md).
