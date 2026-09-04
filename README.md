# Pernorama

Pernorama is a declarative, framework-independent permission node library
for Java. Instead of scattering raw permission strings across your
application code, you declare permission nodes with annotations (or check
them directly) against a `PermissionSubject`.

```java
@Perm("users.create")
public void createUser() {
    // ...
}
```

Pernorama only depends on the JDK. It is not tied to Spring Security,
Discord, JWT, a database, or any other integration — you plug those in by
implementing `PermissionSubject` yourself; see
[Custom PermissionSubject](#custom-permissionsubject).

> **Status: Beta (`0.2.0-beta.1`)** — see [API Stability](#api-stability).

## Installation

Pernorama is published to a self-hosted Maven repository at
`maven.kjh9211.kr`. Add the repository and the dependency:

```groovy
repositories {
    maven { url 'https://maven.kjh9211.kr/releases' }
}

dependencies {
    implementation 'io.pernorama:pernorama:0.2.0-beta.1'
}
```

```xml
<repositories>
    <repository>
        <id>pernorama</id>
        <url>https://maven.kjh9211.kr/releases</url>
    </repository>
</repositories>

<dependency>
    <groupId>io.pernorama</groupId>
    <artifactId>pernorama</artifactId>
    <version>0.2.0-beta.1</version>
</dependency>
```

The repository serves anonymous reads; no credentials are needed to
depend on it.

Alternatively, build the library locally and depend on the resulting
jar, or include the project as a Gradle module:

```bash
./gradlew build
```

```groovy
dependencies {
    implementation project(':pernorama')
}
```

Requires Java 21+.

### Publishing a new version

Publishing requires a Reposilite access token scoped to
`io/pernorama` (`reposiliteUsername`/`reposilitePassword` Gradle
properties, or `REPOSILITE_USERNAME`/`REPOSILITE_PASSWORD`
environment variables). Versions ending in `-SNAPSHOT` go to
`/snapshots`, everything else (including `-beta.n` pre-releases) goes to
`/releases`:

```bash
./gradlew publish
```

Pushing a `v*` tag also publishes automatically via
`.github/workflows/publish.yml`, using the `REPOSILITE_USERNAME` /
`REPOSILITE_PASSWORD` repository secrets.

## Quick Start

```java
PermissionSubject user = new MemoryPermissionSubject();
user.grant("users.create");

PermissionInterceptor interceptor = new PermissionInterceptor();
UserService userService = new UserService();

interceptor.invoke(user, userService, "createUser"); // runs createUser()

user.revoke("users.create");
interceptor.invoke(user, userService, "createUser"); // throws PermissionDeniedException
```

where `UserService` declares:

```java
public class UserService {

    @Perm("users.create")
    public void createUser() {
        // ...
    }
}
```

`PermissionInterceptor` is one way to enforce a permission; you can also
check it directly without reflection — see
[Permission checking without annotations](#permission-checking-without-annotations).

## Permission Nodes

A permission node is a dot-separated identifier such as `users.create`
or `admin.settings.update`. Each segment must be one or more letters,
digits, `_` or `-`; empty segments are not allowed:

```java
PermissionNode node = PermissionNode.of("users.create");

node.name();                                // "users.create"
node.parent();                              // Optional[users]
node.isChildOf(PermissionNode.of("users")); // true
```

The following are all invalid and throw `InvalidPermissionException`:

```text
""              // blank
" "             // blank
".users"        // leading empty segment
"users."        // trailing empty segment
"users..create" // empty segment in the middle
"users create"  // space is not an allowed character
```

`PermissionNode` always represents a concrete, non-wildcard node.
Wildcard patterns (below) are validated and matched separately by
`PermissionResolver`.

## Wildcards

Two wildcard forms can be **granted** (they are never valid as a
required permission node, only as something a `PermissionSubject` holds):

- `*` grants every permission.
- `users.*` grants `users` itself and everything under it
  (`users.create`, `users.delete`, `users.profile.read`, ...), but not
  unrelated groups such as `admin.read`.

```java
PermissionSubject admin = new MemoryPermissionSubject();
admin.grant("users.*");

admin.hasPermission("users.create");      // true
admin.hasPermission("users.profile.read"); // true
admin.hasPermission("admin.read");         // false

PermissionSubject root = new MemoryPermissionSubject();
root.grant("*");

root.hasPermission("anything.at.all"); // true
```

A wildcard is only meaningful as the final segment of a granted pattern.
The matching rule itself lives in one place, `PermissionResolver`, so it
is never re-implemented differently in different parts of the library.

## Annotations

`@Perm` declares the permission node required to invoke a method (or
represented by a type):

```java
@Perm("users.create")
public void createUser() {
}
```

**Resolution rule:** only the annotation declared directly on the
resolved `Method` is used (plain `Method.getAnnotation()` semantics). A
method inherited without being overridden — including an un-overridden
interface default method — is found through its true declaring class, so
its `@Perm` applies normally. **An overriding method does not inherit
the `@Perm` of the method it overrides**, matching how Java annotations
already work; if an override should still require a permission,
redeclare `@Perm` on it explicitly:

```java
class Base {
    @Perm("users.create")
    public void create() { }
}

class Sub extends Base {
    @Override
    public void create() { } // no permission required — @Perm was not inherited
}
```

This is the single rule `PermissionAnnotationResolver` applies; both
`PermissionInterceptor` and `PermissionRegistry` resolve annotations
through it, so there is exactly one implementation of this rule, and its
result is cached per `Method` since it sits on the permission-check hot
path.

### Permission checking without annotations

Annotations and `PermissionInterceptor` are convenient for
reflection-driven invocation, but you don't need either to check a
permission from plain Java code — use `Permission` directly:

```java
boolean allowed = Permission.check(user, "users.create");

Permission.require(user, "users.create"); // throws PermissionDeniedException if missing
```

`subject.hasPermission(...)` itself never throws for "not permitted" —
only `Permission.require(...)` and `PermissionInterceptor.invoke(...)` do,
by throwing `PermissionDeniedException`, which carries the required
permission and the subject that lacked it (without forcing the subject
to be turned into a string).

## Permission Groups

`@PermGroup` prefixes every `@Perm` declared *directly* on the annotated
type (methods and, if present, a type-level `@Perm`) with a common group
name:

```java
@PermGroup("users")
public class UserPermissions {

    @Perm("create")
    public void create() { }

    @Perm("delete")
    public void delete() { }
}
```

This yields the permission nodes `users.create` and `users.delete`.

`@PermGroup` is resolved the same way `@Perm` is: from the *declaring
class of the resolved method*. A subclass that overrides a method does
not inherit its superclass's `@PermGroup` either — if the override
redeclares `@Perm`, it needs its own `@PermGroup` (or no group, for a
fully-qualified value) too.

## Permission Registry

`PermissionRegistry` scans classes for `@PermGroup`/`@Perm` and keeps
track of the resulting permission nodes as queryable metadata — useful
for building an admin UI, validating configuration, or generating
documentation of every permission your application defines:

```java
PermissionRegistry registry = new PermissionRegistry();

registry.register(UserPermissions.class);

registry.contains("users.create");  // true
registry.validate("users.create");  // true: valid syntax AND registered
registry.validate("users.delete_all"); // false: syntactically valid, but not registered
registry.all();                     // every PermissionNode registered so far
```

**Duplicate registration is expected and safe.** The same permission
node commonly guards more than one method (e.g. `delete` and
`bulkDelete` both requiring `users.delete`), and re-registering a class
already scanned is a no-op for nodes already known — neither case is
treated as an error.

`PermissionRegistry` is metadata only: it does not grant or check
anything by itself. It is not thread-safe; populate it once at startup,
before permission checks begin.

## Custom PermissionSubject

`PermissionSubject` is a storage-agnostic interface — Pernorama's core
module does not ship a database, JWT, or Discord integration, but you
can implement the interface directly against whatever you already use:

```java
class DatabaseUser implements PermissionSubject { /* backed by a users table */ }
class DiscordMember implements PermissionSubject { /* backed by Discord roles */ }
class JwtPrincipal implements PermissionSubject { /* backed by a JWT claim */ }
```

At minimum, `hasPermission`/`grant`/`revoke` need to agree on how
granted strings are matched. Reusing `PermissionResolver` gets you the
same wildcard semantics as `MemoryPermissionSubject` for free:

```java
class DatabaseUser implements PermissionSubject {

    private final Set<String> permissions = /* loaded from your storage */;

    @Override
    public boolean hasPermission(String node) {
        return PermissionResolver.matchesAny(permissions, node);
    }

    @Override
    public void grant(String node) { permissions.add(node); }

    @Override
    public void revoke(String node) { permissions.remove(node); }
}
```

`MemoryPermissionSubject` remains the built-in, ready-to-use in-memory
implementation, with the same `grant`/`revoke`/`hasPermission` API.

Nothing in `PermissionSubject` or the rest of the core API depends on
Spring Security, Discord, JWT, OAuth2, a SQL database, or Redis — those
remain out of scope for Beta and are meant to live in separate, optional
modules built on top of this interface.

## Thread Safety

- **`MemoryPermissionSubject`** — thread-safe. `grant`, `revoke` and
  `hasPermission` may be called concurrently from multiple threads
  without external synchronization; the backing store is a
  `ConcurrentHashMap` key set, so reads never block on writes.
- **`PermissionRegistry`** — not thread-safe. It is meant to be
  populated once at startup, on a single thread, before checks begin.
- **`PermissionNode`, `PermissionResolver`, `PermissionAnnotationResolver`,
  `Permission`, `PermissionInterceptor`** — stateless or immutable, and
  safe to share across threads. `PermissionAnnotationResolver`'s
  annotation-resolution cache is itself a `ConcurrentHashMap`.
- Any custom `PermissionSubject` implementation defines its own
  thread-safety; document it the way `MemoryPermissionSubject` does here
  if you expect concurrent callers.

## API Stability

Pernorama is in Beta (`0.2.0-beta.x`). The public API described in this
README is intended to be the shape 1.0 ships with, but it may still
change in a following beta release if a real problem is found — such a
change will be called out in [CHANGELOG.md](CHANGELOG.md) rather than
made silently. Anything not documented here (package-private members,
undocumented behavior) may change at any time.

## License

Pernorama is released under the [MIT License](LICENSE).

---

Develop with codex and claude code
