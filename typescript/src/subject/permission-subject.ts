import { IllegalStateError } from '../error/errors.js';
import { PermissionExplanation } from '../permission/permission-explanation.js';

/**
 * Something that permissions can be granted to and checked against, e.g. a
 * user or a service account.
 *
 * This is a storage-agnostic abstraction: an application is free to back
 * it with a database row, a JWT claim set, a Discord member's roles, or
 * anything else, by implementing this interface directly. The core only
 * ships `MemoryPermissionSubject` as a ready-made in-memory implementation.
 *
 * ## Synchronous
 * Every method answers synchronously, as in Java: a check is a pure
 * evaluation of rules that are already in memory. A subject backed by a
 * database loads what it needs first (`await`), then answers. A
 * `hasPermission` that returns a `Promise` is a bug — a promise is truthy —
 * so everything in this package that consumes a subject requires the
 * answer to be exactly `true` or `false` and throws `IllegalStateError`
 * for anything else instead of treating it as "allowed".
 *
 * ## Contexts
 * Every operation takes an optional **context**: an opaque,
 * application-defined string such as `"academy:123"` identifying the scope
 * a permission applies in. `null` — or an omitted argument — means no
 * context. Pernorama does not generate, parse, validate, or interpret
 * context values; whether a grant without a context also applies inside
 * one is decided by the `ContextPolicy` in use.
 *
 * ## Errors
 * Implementations are expected to throw `InvalidPermissionException` from
 * `grant` and `revoke` for a syntactically invalid rule, to treat an
 * invalid node passed to `hasPermission` the same way, and to throw
 * `IllegalArgumentError` for an empty context.
 */
export interface PermissionSubject {
  /**
   * Returns `true` if this subject has the given permission in `context`,
   * or without a context if `context` is `null` or omitted.
   *
   * @throws InvalidPermissionException if `node` is not a valid node
   * @throws IllegalArgumentError if `context` is empty
   */
  hasPermission(node: string, context?: string | null): boolean;

  /**
   * Explains `hasPermission(node, context)`: the same answer, plus as much
   * of the reason for it as this subject can determine. This is an opt-in
   * diagnostic; `hasPermission` itself does no tracing.
   *
   * Optional. A subject that does not implement it is explained by
   * {@link explainSubject} with only its `hasPermission` answer and
   * `UNAVAILABLE` provenance — never a reason it cannot see. An
   * implementation that stores `PermissionGrant`s can implement it with
   * `ContextPolicy.explain` to report the rules that decided, and must
   * keep the answer equal to `hasPermission`'s: a
   * `CompositePermissionSubject` or a role backed by this subject asks
   * only `explain`, so that a source is queried once.
   *
   * @throws InvalidPermissionException if `node` is not a valid node
   * @throws IllegalArgumentError if `context` is empty
   */
  explain?(node: string, context?: string | null): PermissionExplanation;

  /**
   * Grants a permission rule to this subject, scoped to `context` or to no
   * context if it is `null` or omitted. `rule` may be a concrete node
   * (`"users.create"`), a wildcard pattern (`"users.*"` or `"*"`), or
   * either of those prefixed with `-` to deny instead of allow
   * (`"-users.delete"`).
   *
   * @throws InvalidPermissionException if `rule` is not a valid rule
   * @throws IllegalArgumentError if `context` is empty
   */
  grant(rule: string, context?: string | null): void;

  /**
   * Revokes a previously granted rule. This removes an exact match of a
   * rule **and context** previously passed to `grant`; it does not
   * partially narrow a broader wildcard grant, and it does not touch the
   * same rule granted in another context. Revoking `"users.create"` after
   * granting `"users.*"` has no effect — revoke `"users.*"` itself, or
   * grant the deny rule `"-users.create"` to carve that one node out.
   *
   * @throws InvalidPermissionException if `rule` is not a valid rule
   * @throws IllegalArgumentError if `context` is empty
   */
  revoke(rule: string, context?: string | null): void;
}

/**
 * Whether `value` has the shape of a {@link PermissionSubject}: an object
 * with a `hasPermission` method.
 */
export function isPermissionSubject(value: unknown): value is PermissionSubject {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { hasPermission?: unknown }).hasPermission === 'function'
  );
}

/**
 * `subject.hasPermission(node, context)`, requiring the answer to be a
 * boolean. Anything else — a `Promise` from a subject that was written
 * `async`, `undefined` from one that forgot to return — is a broken
 * subject, and is reported rather than read as an answer.
 *
 * @throws IllegalStateError if the subject did not answer with a boolean
 */
export function checkSubject(subject: PermissionSubject, node: string, context: string | null): boolean {
  const answer: unknown = subject.hasPermission(node, context);
  if (answer !== true && answer !== false) {
    throw new IllegalStateError(
      `hasPermission must return a boolean synchronously, but returned ${describe(answer)}; ` +
        'load the subject before checking it',
    );
  }
  return answer;
}

/**
 * The explanation of `subject`'s answer for `node` in `context`: its own
 * `explain` if it implements one, otherwise its `hasPermission` answer
 * with `UNAVAILABLE` provenance. What Java's default
 * `PermissionSubject.explain` does.
 *
 * @throws IllegalStateError if the subject's `explain` did not return a
 *         `PermissionExplanation`
 */
export function explainSubject(subject: PermissionSubject, node: string, context: string | null): PermissionExplanation {
  if (typeof subject.explain !== 'function') {
    return PermissionExplanation.unavailable(node, context, checkSubject(subject, node, context));
  }
  const explanation: unknown = subject.explain(node, context);
  if (!(explanation instanceof PermissionExplanation)) {
    throw new IllegalStateError(
      `explain must return a PermissionExplanation synchronously, but returned ${describe(explanation)}`,
    );
  }
  return explanation;
}

function describe(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  if (typeof value === 'object' && typeof (value as { then?: unknown }).then === 'function') {
    return 'a Promise';
  }
  return typeof value === 'object' ? 'an object' : `${typeof value} ${String(value)}`;
}
