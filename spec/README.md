# Conformance fixtures

These JSON files describe what a permission check decides, independently
of any programming language. **Every Pernorama implementation runs all
of them**, so the same rules give the same answer everywhere:

| Implementation | Runner | Command |
| --- | --- | --- |
| Java | `src/test/java/pernorama/conformance/ConformanceTest.java` | `./gradlew test --tests 'pernorama.conformance.*'` |
| TypeScript | `typescript/test/conformance/` | `npm run test:conformance` (in `typescript/`) |

CI runs both from one checkout (the `conformance` job).

The Java implementation is the reference. A case here is a statement
about what Java does; if Java fails a fixture, the fixture is wrong. Do
not change an authorization rule in Java to make another language pass —
record the difference as a compatibility blocker instead.

| File | Covers |
| --- | --- |
| `permission-cases.json` | node and rule syntax, single-rule matching, rule-set precedence (specificity, deny ties, default deny), malformed input |
| `context-cases.json` | context validity, `ContextPolicy.applies`, grants, and subjects holding grants under `GLOBAL_FALLBACK` and `EXACT` |
| `role-cases.json` | composite subjects, role and group definitions, assignment cardinality and replacement, resolution policies, context-first resolution, explanations |

## Conventions

- `specVersion` is `1`. A runner refuses a version it does not know, and
  fails on a key it does not know, so a new kind of case cannot be
  skipped silently. Adding cases does not change the version; changing
  what an existing key means does.
- JSON `null` is the absence of a value: no context, or — as a node or
  rule — a missing argument, which is invalid.
- Characters outside printable ASCII are written as `\uXXXX` escapes, so
  that whitespace cases survive editors and diffs.
- A **grant** is a rule string, for a grant without a context, or
  `{ "rule": ..., "context": ... }`.
- A **check** is `{ "node", "context"? }` plus what is expected: either
  `"error"`, or `"allowed"` (for a rule set: `"decision"`), optionally
  with `"decision"` and a full `"explanation"`.
- `"error"` names a kind of failure, not a message:

  | Kind | Java | TypeScript |
  | --- | --- | --- |
  | `INVALID_PERMISSION` | `InvalidPermissionException` | `InvalidPermissionException` |
  | `ILLEGAL_ARGUMENT` | `IllegalArgumentException` | `IllegalArgumentError` |
  | `ILLEGAL_STATE` | `IllegalStateException` | `IllegalStateError` |
  | `UNSUPPORTED_OPERATION` | `UnsupportedOperationException` | `UnsupportedOperationError` |

  When a check has an `"error"`, every way of asking — `hasPermission`,
  `explain`, `Permission.check`, `Permission.require` — has to fail that
  way. When input is invalid in two ways, the fixture pins which is
  reported.

### Explanations

An expected explanation is compared **in full** against the actual one,
after these defaults are filled in for keys that are left out:

```jsonc
{
  "allowed": true,            // required
  "decision": "PERMITTED",    // required; PERMITTED, DENIED, NOT_COVERED or null (unknown)
  "provenance": "COMPLETE",   // required; COMPLETE, PARTIAL or UNAVAILABLE
  "contextPolicy": null,      // GLOBAL_FALLBACK, EXACT or null
  "resolutionPolicy": null,   // ANY_SOURCE, ALLOW_OVERRIDES, DENY_OVERRIDES or null
  "decidingLayer": null,      // EXACT_CONTEXT, GLOBAL_FALLBACK or null
  "matches": [                // in order; default []
    { "rule": "users.*", "context": null, "decisive": false, "deny": false, "wildcard": false }
  ],
  "contributions": [          // in order; default []
    { "source": { "subject": "label" }, "decisive": false, "explanation": { } }
  ]
}
```

In a match, everything but `rule` defaults as shown, so only what is
`true` or non-null is written. A contribution's `source` is either
`{ "subject": <label> }`, naming a source by the `label` it was given in
the fixture, or `{ "role": <id>, "context": <context or null> }` for a
role assignment.

## `permission-cases.json`

| Section | Each case | Asserts |
| --- | --- | --- |
| `nodes` | `{ value, valid }` | `PermissionNode.isValid`, and that `PermissionNode.of` accepts or rejects it |
| `rules` | `{ value, valid }` | `PermissionResolver.isValidPattern`, and that granting it, revoking it, and adding it to a role accept or reject it |
| `nodeRelations` | `{ node, segments, parent, childOf: [{ other, expected }] }` | `segments`, `parent`, `isChildOf` |
| `ruleMatching` | `{ rule, node, matches, denies }` or `{ rule, node, error }` | `PermissionResolver.matches` / `denies` for one rule |
| `ruleSets` | `{ name, rules, checks }` | `decide`, `matchesAny`, `explain`; and that a role built from the same rules permits and denies the same nodes |

## `context-cases.json`

| Section | Each case | Asserts |
| --- | --- | --- |
| `contexts` | `{ value, valid }` | `PermissionGrant.isValidContext` / `requireValidContext` |
| `applies` | `{ policy, granted, requested, applies }` or `error` | `ContextPolicy.applies` |
| `grants` | `{ rule, context, text }` or `error` | constructing a `PermissionGrant`, and its string form |
| `subjects` | `{ name, policy, grants, revoke?, checks }` | an in-memory subject created through a `Pernorama` instance with that policy: `grant` each of `grants`, then `revoke` each of `revoke`, then every check — and that `ContextPolicy.permits` / `explain` over the subject's grants agree |

## `role-cases.json`

| Section | Each case | Asserts |
| --- | --- | --- |
| `ids` | `{ value, valid }` | the id is accepted or rejected for both a role and a group |
| `groupDefinitions` | `{ min?, max?, policy?, valid, expectMin?, expectMax? }` | building a group with those limits |
| `composites` | `{ name, sources, checks }` | a `CompositePermissionSubject` over `sources`, which is also read-only |
| `scenarios` | `{ name, contextPolicy, groups?, roles, steps }` | a sequence of operations on one `RoleAssignments` |

A **source** (and the `subject` backing a role) is one of:

| `kind` | Is |
| --- | --- |
| `memory` | an in-memory subject with `policy` and `grants` |
| `opaque` | a custom subject that holds the same grants but implements only the mandatory methods, so it cannot explain itself |
| `failing` | a subject whose every call fails with `ILLEGAL_STATE` |
| `composite` | a composite over its own `sources` |

A **group** is `{ key?, id, min?, max?, policy? }` and a **role** is
`{ key?, id, group?, rules? }` or `{ key?, id, group?, subject }`. Steps
refer to roles and groups by `key`, which defaults to `id`; two entries
with one `id` and different `key`s are how conflicting definitions are
written. `policy` is `REJECT`, `REPLACE_EXISTING`, `REPLACE_OLDEST`,
`REPLACE_NEWEST`, or one of two deliberately broken custom policies:
`BROKEN_REPLACE_NONE` (replaces nothing) and `BROKEN_REPLACE_REQUESTED`
(replaces the role being assigned, which the target does not hold).

Steps, by `op`:

| `op` | Fields | Asserts |
| --- | --- | --- |
| `assign`, `unassign` | `target`, `role`, `context?`, and `expect: { status, removed, current, reason? }` or `error` | the result; on `error`, also that the target's assignments did not change |
| `roles` | `target`, `context?`, `expect` (role ids) or `error` | the roles held in exactly that context |
| `assignments` | `target`, `expect: [{ role, context? }]` | every assignment, oldest first |
| `check` | `target`, `resolution?`, and a check | the target's role-assignment subject under that resolution policy |
| `roleDenies` | `role`, `node`, `expect` or `error` | `Role.denies` |
| `rolePermits` | `role`, `node`, `context?`, `expect` or `error` | the role's own `permissions` subject |

`resolution` is `ALLOW_OVERRIDES` (the default), `DENY_OVERRIDES`, or
`CUSTOM_ANY`: a custom policy that permits if any applicable role
permits, with no layering, used to pin how a policy the library does not
know is explained.

## Adding a case

1. Add it to the fixture, with the expectation written by hand from the
   documented rules — not copied from an implementation's output.
2. Run the Java suite. If it disagrees, reread the rule: the fixture is
   what has to change.
3. Run every other implementation's suite.
