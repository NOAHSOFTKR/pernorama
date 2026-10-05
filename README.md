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

> **Status: Beta (`0.3.0`)** — see [API Stability](#api-stability).

## Installation

Pernorama is published to a self-hosted Maven repository at
`maven.noahsoft.kr`. Add the repository and the dependency:

```groovy
repositories {
    maven { url 'https://maven.noahsoft.kr/releases' }
}

dependencies {
    implementation 'io.pernorama:pernorama:0.3.0'
}
```

```xml
<repositories>
    <repository>
        <id>pernorama</id>
        <url>https://maven.noahsoft.kr/releases</url>
    </repository>
</repositories>

<dependency>
    <groupId>io.pernorama</groupId>
    <artifactId>pernorama</artifactId>
    <version>0.3.0</version>
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
"-users.create" // a leading - marks a deny rule, not a node
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

## Deny Rules

A rule prefixed with `-` denies instead of allows, so a broad grant can
have exceptions carved out of it:

```java
PermissionSubject moderator = new MemoryPermissionSubject();
moderator.grant("users.*");
moderator.grant("-users.delete");

moderator.hasPermission("users.create"); // true
moderator.hasPermission("users.delete"); // false
```

**The most specific rule covering the node decides**, and a deny rule
wins a tie. Specificity is: an exact rule beats a wildcard rule, and
between two wildcard rules the one with more segments before the `*`
wins (`users.profile.*` beats `users.*`, which beats `*`). So the
reverse arrangement works too — deny a group and allow one node back
into it:

```java
PermissionSubject auditor = new MemoryPermissionSubject();
auditor.grant("*");
auditor.grant("-users.*");
auditor.grant("users.read");

auditor.hasPermission("posts.read");   // true, from *
auditor.hasPermission("users.create"); // false, from -users.*
auditor.hasPermission("users.read");   // true, the exact rule wins
```

A node that no rule covers is still not permitted; deny rules are for
overriding a broader grant, not for expressing the default.

An exact rule covers exactly its own node, and that holds for deny
rules too — `-users.delete` does **not** deny `users.delete.hard`,
which the surrounding `users.*` still permits. Deny the wildcard form
to close a subtree:

```java
PermissionSubject editor = new MemoryPermissionSubject();
editor.grant("users.*");
editor.grant("-users.delete.*"); // users.delete and everything under it

editor.hasPermission("users.delete");      // false
editor.hasPermission("users.delete.hard"); // false
```

`revoke` removes a rule by its exact string, deny rules included, so
`revoke("-users.delete")` puts `users.delete` back under the
`users.*` grant.

Because a leading `-` marks a deny rule, **a permission node may never
start with `-`**. The character is still legal anywhere else, so
`users.soft-delete` is an ordinary node.

`PermissionResolver` exposes the single-rule primitives behind all of
this: `matches(rule, node)` answers "does this rule *allow* the node"
and is therefore `false` for any deny rule, and `denies(rule, node)` is
its mirror. `matchesAny(rules, node)` is the one that applies the
precedence above to a whole set; a subject whose grants can carry a
context goes through `ContextPolicy.permits` instead, which applies the
same precedence within each context (see [Contexts](#contexts)).

## Contexts

A grant can be scoped to a **context**, so the same subject can hold a
permission in one scope and not another — the shape of multi-tenant or
resource-grouped authorization:

```text
students.read @ academy:123
guild.manage  @ guild:987654321
project.write @ project:01J8XYZ...
```

> A context is an opaque, application-defined string identifying the
> scope in which a permission applies. Pernorama does not generate,
> parse, validate, or interpret context values.

Every `grant`, `revoke` and `hasPermission` takes an optional context
as its second argument; leaving it out is the same as passing `null`,
which means "no context":

```java
Pernorama pernorama = Pernorama.builder()
        .contextPolicy(ContextPolicy.GLOBAL_FALLBACK)
        .build();

MemoryPermissionSubject user = pernorama.newSubject();
user.grant("students.read");
user.grant("students.edit", "academy:123");

user.hasPermission("students.read");                 // true
user.hasPermission("students.read", "academy:456");  // true, a global grant applies everywhere
user.hasPermission("students.edit", "academy:123");  // true
user.hasPermission("students.edit", "academy:456");  // false
user.hasPermission("students.edit");                 // false

user.revoke("students.edit", "academy:123");         // removes only that grant
```

Two contexts match only if they are equal strings. `academy:*` is not
a wildcard, `academy` is not a parent of `academy:123`, and
`role == ADMIN` is not an expression — they are just strings. The one
rule Pernorama applies is that "no context" has a single spelling,
`null`; an empty string is rejected with `IllegalArgumentException`.

`Permission.check` and `Permission.require` take a context too, and the
`PermissionDeniedException` thrown by `require` reports it in
`context()`.

### Context policy

Whether a grant *without* a context also applies *inside* one is
decided by the `ContextPolicy`, chosen once for a whole `Pernorama`
instance — individual permissions never carry their own:

- **`GLOBAL_FALLBACK`** (the default) — a grant without a context is
  global and applies in every context, underneath the grants made for
  that context.
- **`EXACT`** — grants with and without a context are separate. A check
  in `academy:123` sees only grants scoped to exactly `academy:123`.

```java
Pernorama strict = Pernorama.builder()
        .contextPolicy(ContextPolicy.EXACT)
        .build();

MemoryPermissionSubject user = strict.newSubject();
user.grant("students.read");

user.hasPermission("students.read");                // true
user.hasPermission("students.read", "academy:123"); // false

user.grant("students.read", "academy:123");

user.hasPermission("students.read", "academy:123"); // true
```

Under both policies a check *without* a context sees only grants
without one. Create subjects and role assignments through your
`Pernorama` instance so they all share its policy —
`pernorama.newSubject(List.of(...))` pre-grants rules the same way; the
constructors that take no policy (`new MemoryPermissionSubject()`,
`new MemoryPermissionSubject(rules)`, `new RoleAssignments<>()`) use
`GLOBAL_FALLBACK`. An application that needs different semantics for
different domains uses one instance per domain.

### Contexts and deny rules

Under `GLOBAL_FALLBACK`, a check in a context goes through two layers:

1. **The grants scoped to that context.** If any of their rules — allow
   or deny — covers the node, they decide, with the usual precedence
   among themselves.
2. **Only if none of them covers it**, the grants without a context
   decide.

So a context can carve an exception out of a global grant:

```java
MemoryPermissionSubject teacher = pernorama.newSubject();
teacher.grant("students.*");
teacher.grant("-students.delete", "academy:123");

teacher.hasPermission("students.delete", "academy:123"); // false
teacher.hasPermission("students.delete", "academy:456"); // true
```

A context overrides the global grants for **every node it says anything
about**, even with a less specific rule than the global one — and it
can re-allow what a global rule denies:

```java
MemoryPermissionSubject manager = pernorama.newSubject();
manager.grant("students.delete");
manager.grant("-students.*", "academy:123");

manager.hasPermission("students.delete", "academy:123"); // false, the context covers it
manager.hasPermission("students.delete", "academy:456"); // true, falls back to the global grant
```

Within one layer nothing changes: the most specific rule decides and a
deny wins a tie. Under `EXACT` there is only one layer, the grants in
the checked context. `PermissionResolver` itself never sees a context;
`ContextPolicy` only decides which grants it is given, and in what
order.

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
path. The cache lives on the method's declaring class, so a class that is
discarded — a generated proxy, say — takes its entries with it.

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

An implementation provides the three methods that take a context —
`hasPermission(node, context)`, `grant(node, context)` and
`revoke(node, context)`; the overloads without one are default methods
passing `null`. The three need to agree on how granted rules are
matched. Storing `PermissionGrant`s (a rule plus a nullable context) and
asking your instance's `ContextPolicy` gets you the same wildcard,
deny-rule and context semantics as `MemoryPermissionSubject` for free:

```java
class DatabaseUser implements PermissionSubject {

    private final ContextPolicy contextPolicy;
    private final Set<PermissionGrant> grants = new HashSet<>(); // loaded from your storage

    DatabaseUser(Pernorama pernorama) {
        this.contextPolicy = pernorama.contextPolicy();
    }

    @Override
    public boolean hasPermission(String node, String context) {
        return contextPolicy.permits(grants, node, context);
    }

    @Override
    public void grant(String node, String context) {
        grants.add(new PermissionGrant(node, context));
    }

    @Override
    public void revoke(String node, String context) {
        grants.remove(new PermissionGrant(node, context));
    }
}
```

In a table this is one row per grant — subject, rule, and a nullable
context column. Load the rows for the subject whose context is the
checked one or `NULL`, and let `permits` decide: the rule column can
hold wildcards and deny rules, so the decision cannot be a plain
`WHERE permission = ?`.

A subject that never uses contexts can match plain rule strings with
`PermissionResolver.matchesAny` — and should answer a contextual check
explicitly rather than ignore the context:

```java
class ApiKey implements PermissionSubject {

    private final Set<String> rules = new HashSet<>();

    @Override
    public boolean hasPermission(String node, String context) {
        PermissionGrant.requireValidContext(context);
        return PermissionResolver.matchesAny(rules, node) && context == null;
    }

    @Override
    public void grant(String node, String context) {
        rules.add(ruleWithoutContext(node, context));
    }

    @Override
    public void revoke(String node, String context) {
        rules.remove(ruleWithoutContext(node, context));
    }

    private static String ruleWithoutContext(String node, String context) {
        PermissionGrant grant = new PermissionGrant(node, context); // validates both
        if (grant.hasContext()) {
            throw new UnsupportedOperationException("API keys have no contexts");
        }
        return grant.rule();
    }
}
```

`MemoryPermissionSubject` remains the built-in, ready-to-use in-memory
implementation, with the same `grant`/`revoke`/`hasPermission` API. To
extend it — to audit checks, say — override the methods that take a
context: its overloads without one are `final`, because callers that
pass a context, such as `CompositePermissionSubject`, call the
two-argument methods directly.

Nothing in `PermissionSubject` or the rest of the core API depends on
Spring Security, Discord, JWT, OAuth2, a SQL database, or Redis — those
remain out of scope for Beta and are meant to live in separate, optional
modules built on top of this interface.

## Roles and Composition

`CompositePermissionSubject` answers from several subjects at once —
the usual "a user holds roles, and each role carries permissions"
shape:

```java
PermissionSubject admins = new MemoryPermissionSubject(List.of("users.*"));
PermissionSubject own = new MemoryPermissionSubject(List.of("profile.edit"));

PermissionSubject user = new CompositePermissionSubject(own, admins);

user.hasPermission("users.create"); // true, from the admins role
user.hasPermission("profile.edit"); // true, from the user's own grants
user.hasPermission("posts.delete"); // false, from neither
```

The sources can be any `PermissionSubject`, so a role loaded from your
database and an in-memory set of personal grants compose the same way.

`hasPermission` is `true` if **any** source says so. Each source
evaluates its own rules on its own, which means **a deny rule only
limits the source holding it** — if one role denies `users.delete` and
another source grants it, the answer is `true`.

So a deny rule cannot ban one subject from something another source
grants: a composite of a personal `-users.delete` and an
everyone-role `*` permits `users.delete`. Take the permission out of
the source that grants it, or give that subject a narrower role;
composing sources adds permissions, it never subtracts them.

A composite is read-only: it has no storage of its own, so `grant` and
`revoke` throw `UnsupportedOperationException`. Modify the source you
actually mean instead.

## Role Groups and Assignments

`CompositePermissionSubject` is enough when you only need to *check*
permissions from several sources. When roles need rules about which
of them a user may hold together — "exactly one subscription plan at a
time" — the `pernorama.role` package adds named roles, groups with
cardinality limits, and an assignment API that enforces them. It sits
on top of the core: nothing in `PermissionSubject` changes, and you do
not need it if you don't use roles.

```java
RoleGroup plan = RoleGroup.builder("plan")
        .minAssignments(0)
        .maxAssignments(1)
        .assignmentPolicy(RoleAssignmentPolicy.REPLACE_EXISTING)
        .build();

Role pro = Role.builder("plan_pro")
        .group(plan)
        .permission("app.use")
        .permission("app.plan.pro")
        .build();

Role max5 = Role.builder("plan_max_5")
        .group(plan)
        .permission("app.use")
        .permission("app.plan.max5")
        .build();

RoleAssignments<String> assignments = new RoleAssignments<>();

assignments.assign("alice", pro);                                // ASSIGNED
RoleAssignmentResult result = assignments.assign("alice", max5);

result.status();         // REPLACED
result.previousRole();   // Optional[plan_pro]
result.currentRole();    // Optional[plan_max_5]
assignments.roles("alice"); // [plan_max_5]

PermissionSubject alice = assignments.subject("alice");
alice.hasPermission("app.plan.max5"); // true
alice.hasPermission("app.plan.pro");  // false
```

- **`Role`** — a named bundle of permission rules, or a wrapper around
  an existing `PermissionSubject` via `.permissions(subject)`, e.g. one
  loaded from your database. What it permits is answered with the same
  rules, wildcards and deny semantics as everywhere else; the role layer
  does no matching of its own. A role is identified by its id, and a
  target keeps the `Role` instance it was assigned: assigning a new
  definition with the same id is `NO_CHANGE` and does not update it. To
  change a role's permissions in place, back it with a subject you
  update, or store role ids and resolve them in your own
  `RoleAssignmentStore`.
- **`RoleGroup`** — `minAssignments`/`maxAssignments` for a set of
  related roles (defaults: `0` and unbounded), plus the
  `RoleAssignmentPolicy` that decides what happens when an assignment
  would go over the maximum. A group is identified by its id, so build
  each group once and share it: if two roles carry same-id groups with
  different limits or policies, `RoleAssignments` throws
  `IllegalStateException` rather than let the choice of role decide
  which limits apply.
- **`RoleAssignments`** — `assign`, `unassign`, `roles`, and `subject`
  for a target identified by any key type (a user id, say). Storage is
  pluggable through `RoleAssignmentStore`; the default is the in-memory
  `MemoryRoleAssignmentStore`.

### Assignment rules

- **Assigning a role the target already holds is a no-op**:
  `NO_CHANGE`, and the group's policy is never consulted.
- **Going over `maxAssignments`** is handed to the group's policy.
  `REJECT` (the default) leaves the target as it was; `REPLACE_EXISTING`
  replaces every role held in the group — in an exclusive group, the one
  role (so it cannot be combined with a `minAssignments` above 1);
  `REPLACE_OLDEST` and `REPLACE_NEWEST` replace as few roles as needed,
  picked by assignment order.
- **`minAssignments` is enforced on `unassign`**: removing a role that
  would take the target under the minimum is `REJECTED`. A target that
  starts under the minimum, as every target does before its first
  assignment, can still be assigned roles.
- **A replacement is atomic.** The old roles leave and the new one
  arrives in a single write, so the target is never seen holding
  neither. `RoleAssignmentStore` is a read plus a compare-and-set, and
  that is the contract a database-backed store has to keep — typically
  with one transaction or a version column.
- **Every call returns a `RoleAssignmentResult`**: `ASSIGNED`,
  `REPLACED`, `UNASSIGNED`, `NO_CHANGE` or `REJECTED`, with the roles
  removed and a rejection reason — enough to emit an audit event from.
  Pernorama does not store audit logs itself.

A group's policy can also be your own. It receives the group, the
roles held in it (oldest first) and the requested role, and returns
`RoleAssignmentDecision.reject(reason)` or
`RoleAssignmentDecision.replace(roles)`. `RoleAssignments` checks the
decision before writing anything and throws `IllegalStateException` if
it would still break the group's limits:

```java
RoleAssignmentPolicy keepLifetime = (group, held, requested) ->
        held.stream().anyMatch(r -> r.id().equals("plan_lifetime"))
                ? RoleAssignmentDecision.reject("lifetime plans are never replaced")
                : RoleAssignmentDecision.replace(held);
```

### Combining the permissions of several roles

Which roles may coexist and how their permissions combine are separate
questions. The second is a `PermissionResolutionPolicy`, passed to
`subject(target, policy)`:

- **`ALLOW_OVERRIDES`** (the default for `subject(target)`) — permitted
  if any role permits the node; a deny rule only limits the role holding
  it. Without contexts this is exactly `CompositePermissionSubject`'s
  behavior.
- **`DENY_OVERRIDES`** — permitted if some role permits the node and no
  role *explicitly denies* it, so a deny rule in one role vetoes a grant
  in another. A role that simply does not mention the node vetoes
  nothing, and only a role built from rules can deny.

Both combine the roles of one layer. In a check with a context, roles
held in that context come before roles held without one, so a global
deny does not veto a role held in the context that covers the node —
see [Roles in a context](#roles-in-a-context).

```java
Role editor = Role.builder("editor").permission("users.*").build();
Role suspended = Role.builder("suspended").permission("-users.delete").build();

assignments.assign("bob", editor);
assignments.assign("bob", suspended);

assignments.subject("bob").hasPermission("users.delete"); // true
assignments.subject("bob", PermissionResolutionPolicy.DENY_OVERRIDES)
        .hasPermission("users.delete");                   // false
```

`PermissionResolutionPolicy` is a one-method interface over the
target's assignments that apply to the check (see
[Roles in a context](#roles-in-a-context)), so a different
interpretation — ranking roles by group, say — is a lambda away.

The subject is a read-only live view: each check reads the target's
current roles, and `grant`/`revoke` throw
`UnsupportedOperationException`. For permissions granted to a user
directly, compose it: `new CompositePermissionSubject(own,
assignments.subject("alice"))`.

### Roles in a context

A role can be assigned in a [context](#contexts) — a teacher in one
academy and a student in another:

```java
Role teacher = Role.builder("teacher").permission("students.*").build();
Role student = Role.builder("student").permission("students.read").build();

RoleAssignments<String> assignments = pernorama.newRoleAssignments();
assignments.assign("alice", teacher, "academy:123");
assignments.assign("alice", student, "academy:456");

PermissionSubject alice = assignments.subject("alice");
alice.hasPermission("students.edit", "academy:123"); // true, as a teacher
alice.hasPermission("students.edit", "academy:456"); // false, only a student there
alice.hasPermission("students.read", "academy:456"); // true

assignments.roles("alice", "academy:123"); // [teacher]
```

- **The context belongs to the assignment, not the role.** A role's
  rules are the same wherever it is held, so one `teacher` role serves
  every academy. `assign`, `unassign` and `roles` take the context as a
  third argument; without one they mean "no context", exactly like
  `grant`. The same role can be held in several contexts, and
  `unassign` removes it from one.
- **Where an assignment applies is up to the `ContextPolicy`**, as for
  a grant: under `GLOBAL_FALLBACK` a role assigned without a context
  applies in every context, under `EXACT` only to checks without one;
  a role assigned in a context applies only there. `roles(target,
  context)` lists what is held in exactly that context — so
  `roles(target)` lists only the roles held without one — and
  `assignments(target)` every `RoleAssignment` in every context.
- **Group limits are counted per context.** Being a teacher in
  `academy:123` does not stop an exclusive `membership` group from
  holding a student role in `academy:456`; assignments without a
  context are counted together as one more context. A replacement only
  ever removes roles from the context being assigned in, and a policy
  is only shown the roles held there. A group id still has one
  definition everywhere: a conflicting definition held in any context
  fails the call.
- **Roles held in the context come first, as grants do.** Under
  `GLOBAL_FALLBACK` the built-in policies see two layers, exactly like
  [grants in a context](#contexts-and-deny-rules): if any role held in
  the checked context permits or denies the node, those roles decide,
  combined as above, and the roles held without a context decide only
  otherwise. So a role held in `academy:123` can narrow or re-allow what
  a global role says — in `academy:123` only — under either policy:

  ```java
  Role restricted = Role.builder("restricted").permission("-students.*").build();
  assignments.assign("bob", restricted);           // no context
  assignments.assign("bob", teacher, "academy:123");

  PermissionSubject bob = assignments.subject("bob", PermissionResolutionPolicy.DENY_OVERRIDES);
  bob.hasPermission("students.edit", "academy:123"); // true, the teacher role decides there
  bob.hasPermission("students.edit", "academy:456"); // false, only the global role applies
  ```

  A custom policy receives every applicable `RoleAssignment`, from both
  layers, and the context, and decides for itself how they relate.
- **A role's own `permissions()` has no contexts.** Asked directly, a
  role built from rules answers only checks without a context and is
  `false` for a check in one, under either policy — like any subject
  without contexts (see [Custom PermissionSubject](#custom-permissionsubject)).
  Hold a role in a context through `RoleAssignments` instead of
  composing `role.permissions()` into a `CompositePermissionSubject`.
- **Results and stores carry the context.** `RoleAssignmentResult.context()`
  says where a change happened, and `RoleAssignmentStore` reads and
  compare-and-sets a list of `RoleAssignment`s — one row per target,
  role id and nullable context in a relational store.

## Thread Safety

- **`MemoryPermissionSubject`** — thread-safe. `grant`, `revoke` and
  `hasPermission` may be called concurrently from multiple threads
  without external synchronization; the backing store is a
  `ConcurrentHashMap` key set, so reads never block on writes. Each
  call is atomic on its own, but a *multi-rule* update is not: between
  `grant("users.*")` and `grant("-users.delete")` another thread can
  still see `users.delete` permitted. Pass the whole rule set to
  `pernorama.newSubject(rules)` or the constructor before the subject
  is shared, or synchronize the update yourself.
- **`CompositePermissionSubject`** — immutable in itself; its source
  list is copied when it is constructed. Whether concurrent use is safe
  therefore depends entirely on the subjects it was given.
- **`RoleAssignments`** — thread-safe as long as its
  `RoleAssignmentStore` keeps the store contract;
  `MemoryRoleAssignmentStore` does. Concurrent assignments to the same
  target never leave a group over its limits: each one re-decides from
  fresh state if another got there first, so a custom
  `RoleAssignmentPolicy` may be called more than once and should have no
  side effects. `Role` (built from rules), `RoleGroup` and
  `RoleAssignment` are immutable; a role built from a subject is as
  thread-safe as that subject.
- **`PermissionRegistry`** — not thread-safe. It is meant to be
  populated once at startup, on a single thread, before checks begin.
- **`Pernorama`, `ContextPolicy`, `PermissionGrant`, `PermissionNode`,
  `PermissionResolver`, `PermissionAnnotationResolver`, `Permission`,
  `PermissionInterceptor`** — stateless or immutable, and
  safe to share across threads. `PermissionAnnotationResolver` caches
  resolution in a `ConcurrentHashMap` per declaring class.
- Any custom `PermissionSubject` implementation defines its own
  thread-safety; document it the way `MemoryPermissionSubject` does here
  if you expect concurrent callers.

## API Stability

Pernorama is in Beta (`0.x`). The public API described in this
README is intended to be the shape 1.0 ships with, but it may still
change in a following 0.x release if a real problem is found — such a
change will be called out in [CHANGELOG.md](CHANGELOG.md) rather than
made silently. Anything not documented here (package-private members,
undocumented behavior) may change at any time.

What is still open between Beta and 1.0 — and what 1.0 itself
commits to — is described in [ROADMAP.md](ROADMAP.md).

## License

Pernorama is released under the [MIT License](LICENSE).

---

Develop with codex and claude code
