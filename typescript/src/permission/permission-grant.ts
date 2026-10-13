import { IllegalArgumentError, InvalidPermissionException } from '../error/errors.js';
import { isValidPattern } from './syntax.js';

/**
 * One granted permission rule, optionally scoped to a context:
 *
 * ```ts
 * new PermissionGrant('students.read');                // no context
 * new PermissionGrant('students.edit', 'academy:123'); // only in academy:123
 * ```
 *
 * The {@link rule} is anything `PermissionSubject.grant` accepts — a node,
 * a wildcard, or either prefixed with `-` to deny.
 *
 * ## Contexts
 * A context is an opaque, application-defined string identifying the scope
 * in which a permission applies. Pernorama does not generate, parse,
 * validate, or interpret context values: `"academy:123"`, `"academy:*"`
 * and `"academy"` are three unrelated strings, compared only for equality.
 *
 * The one rule Pernorama does apply is that "no context" has exactly one
 * stored spelling, `null`: the empty string is rejected rather than
 * treated as either a context or the absence of one. (Parameters also
 * accept `undefined`, an omitted argument, as `null`.) Whether a grant
 * with no context also applies inside a context is decided by the
 * `ContextPolicy`, not stored here.
 */
export class PermissionGrant {
  /** A valid permission rule. */
  readonly rule: string;
  /** The context the rule is scoped to, or `null` for none. */
  readonly context: string | null;

  /**
   * @throws InvalidPermissionException if `rule` is not a syntactically
   *         valid permission rule
   * @throws IllegalArgumentError if `context` is empty or not a string
   */
  constructor(rule: string, context?: string | null) {
    if (!isValidPattern(rule)) {
      throw new InvalidPermissionException(rule);
    }
    this.rule = rule;
    this.context = PermissionGrant.requireValidContext(context);
    Object.freeze(this);
  }

  /** Whether this grant is scoped to a context. */
  get hasContext(): boolean {
    return this.context !== null;
  }

  /**
   * Returns `true` if `context` is acceptable wherever Pernorama takes
   * one: `null`/`undefined` (no context) or any non-empty string.
   */
  static isValidContext(context: unknown): context is string | null | undefined {
    return context === null || context === undefined || (typeof context === 'string' && context.length > 0);
  }

  /**
   * Returns `context` if it {@link PermissionGrant.isValidContext is valid},
   * with `undefined` normalized to `null`.
   *
   * @throws IllegalArgumentError if `context` is empty or not a string
   */
  static requireValidContext(context: unknown): string | null {
    if (!PermissionGrant.isValidContext(context)) {
      throw new IllegalArgumentError('context must be null or non-empty');
    }
    return context ?? null;
  }

  /** Two grants are equal if they have the same rule and the same context. */
  equals(other: unknown): boolean {
    return other instanceof PermissionGrant && other.rule === this.rule && other.context === this.context;
  }

  toString(): string {
    return this.context === null ? this.rule : `${this.rule} @ ${this.context}`;
  }
}
