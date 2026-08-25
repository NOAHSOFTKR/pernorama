# Pernorama

Pernorama is a declarative permission node library for Java. Instead of
scattering raw permission strings across your application code, you
declare permission nodes with annotations and check them against a
`PermissionSubject`.

```java
@Perm("users.create")
public void createUser() {
    // ...
}
```

Pernorama is not tied to any application framework (Spring, Minecraft,
Discord, ...). It only depends on the JDK and exposes a small, plain
Java API that can be wrapped by framework-specific integrations later.

## Installation

Pernorama is a Gradle project. Build the library locally and depend on
the resulting jar, or include the project as a Gradle module:

```bash
./gradlew build
```

```groovy
dependencies {
    implementation project(':pernorama')
}
```

Requires Java 21+.

## Basic usage

Declare a permission on a method with `@Perm`:

```java
public class UserService {

    @Perm("users.create")
    public void createUser() {
        System.out.println("created");
    }
}
```

Create a subject and grant it a permission:

```java
PermissionSubject user = new MemoryPermissionSubject();
user.grant("users.create");

user.hasPermission("users.create"); // true
```

Enforce the annotation with a `PermissionInterceptor`:

```java
PermissionInterceptor interceptor = new PermissionInterceptor();
UserService userService = new UserService();

interceptor.invoke(user, userService, "createUser");
```

If `user` does not have `users.create`, this throws
`PermissionDeniedException` instead of calling the method.

## `@Perm`

Declares a permission node on a method or type. Available at runtime.

```java
@Perm("users.create")
public void createUser() { }
```

## `@PermGroup`

Groups the `@Perm`s declared in a class under a common prefix. Available
at runtime, applicable to types only.

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

## `PermissionNode`

A parsed, immutable permission identifier, with parent/child
relationships between dotted segments:

```java
PermissionNode node = PermissionNode.of("users.create");

node.name();                                          // "users.create"
node.parent();                                        // Optional[users]
node.isChildOf(PermissionNode.of("users"));            // true
```

## `PermissionSubject`

Something permissions can be granted to and checked against.
`MemoryPermissionSubject` is the in-memory MVP implementation:

```java
PermissionSubject user = new MemoryPermissionSubject();

user.grant("users.create");
user.hasPermission("users.create");         // true
user.hasPermission(PermissionNode.of("users.create")); // true

user.revoke("users.create");
user.hasPermission("users.create");         // false
```

`revoke` removes an exact match of a string previously passed to
`grant`; it does not narrow a broader wildcard grant. To take back a
wildcard grant, revoke the same wildcard string.

## `PermissionRegistry`

Scans classes for `@PermGroup`/`@Perm` and registers the resulting
permission nodes:

```java
PermissionRegistry registry = new PermissionRegistry();
registry.register(UserPermissions.class);

PermissionNode node = registry.get("users.create");
registry.all(); // every node registered so far
```

## Wildcard

`MemoryPermissionSubject` and `PermissionResolver` support two wildcard
forms:

- `*` grants every permission.
- `users.*` grants `users` itself and everything under it
  (`users.create`, `users.delete`, `users.create.special`, ...), but not
  unrelated groups such as `posts.create`.

```java
PermissionSubject admin = new MemoryPermissionSubject();
admin.grant("users.*");

admin.hasPermission("users.create"); // true
admin.hasPermission("users.delete"); // true
admin.hasPermission("posts.create"); // false

PermissionSubject root = new MemoryPermissionSubject();
root.grant("*");
root.hasPermission("anything.at.all"); // true
```

## Full example

```java
@PermGroup("users")
public class UserPermissions {

    @Perm("create")
    public void create() { }

    @Perm("delete")
    public void delete() { }
}

public class UserService {

    @Perm("users.create")
    public void createUser() {
        System.out.println("created");
    }
}

public class Main {
    public static void main(String[] args) throws Exception {
        PermissionRegistry registry = new PermissionRegistry();
        registry.register(UserPermissions.class);

        PermissionSubject user = new MemoryPermissionSubject();
        user.grant("users.create");

        PermissionInterceptor interceptor = new PermissionInterceptor();
        UserService userService = new UserService();

        interceptor.invoke(user, userService, "createUser"); // "created"

        user.revoke("users.create");
        interceptor.invoke(user, userService, "createUser"); // throws PermissionDeniedException
    }
}
```
