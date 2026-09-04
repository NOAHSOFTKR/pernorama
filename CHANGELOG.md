# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  `maven.kjh9211.kr`, with sources and javadoc jars and a tag-triggered publish
  workflow.

[0.2.0-beta.1]: https://github.com/NOAHSOFTKR/pernorama/releases/tag/v0.2.0-beta.1
[0.1.0]: https://github.com/NOAHSOFTKR/pernorama/commit/ccd6e69734c4b82c74a905d53afbd46422afe97d
