import { IllegalArgumentError } from '../error/errors.js';
import { ContextPolicy } from '../permission/context-policy.js';
import { PermissionExplanation } from '../permission/permission-explanation.js';
import { PermissionGrant } from '../permission/permission-grant.js';
import { PermissionNode } from '../permission/permission-node.js';
import { checkSubject, type PermissionSubject } from './permission-subject.js';

/**
 * An in-memory {@link PermissionSubject} backed by a set of
 * {@link PermissionGrant grants}: permission rules, which may include deny
 * rules such as `"-users.delete"`, each optionally scoped to a context.
 * `PermissionResolver` decides which rule wins when several cover the same
 * node, and the subject's {@link ContextPolicy} decides which grants apply
 * in a context.
 *
 * Create one with `pernorama.newSubject()` so it uses the policy your
 * application chose. Without a policy it uses
 * `ContextPolicy.GLOBAL_FALLBACK`, the default of `Pernorama.builder()`.
 *
 * Every call is synchronous and atomic on its own. A rule set built from
 * several calls is not: code that runs between `grant('users.*')` and
 * `grant('-users.delete')` — across an `await`, say — observes
 * `users.delete` as permitted. Populate the subject before sharing it.
 */
export class MemoryPermissionSubject implements PermissionSubject {
  readonly #contextPolicy: ContextPolicy;
  readonly #grants = new Map<string, PermissionGrant>();

  /** Creates an empty subject using `ContextPolicy.GLOBAL_FALLBACK`. */
  constructor();
  /** Creates a subject using `GLOBAL_FALLBACK`, pre-granted with the given rules, without a context. */
  constructor(initialPermissions: Iterable<string>);
  /** Creates a subject that applies `contextPolicy`, optionally pre-granted with the given rules, without a context. */
  constructor(contextPolicy: ContextPolicy, initialPermissions?: Iterable<string>);
  constructor(first?: ContextPolicy | Iterable<string>, second?: Iterable<string>) {
    let initial: Iterable<string> | undefined;
    if (first instanceof ContextPolicy) {
      this.#contextPolicy = first;
      initial = second;
    } else if (first === undefined && second === undefined) {
      this.#contextPolicy = ContextPolicy.GLOBAL_FALLBACK;
    } else if (isIterable(first) && typeof first !== 'string' && second === undefined) {
      this.#contextPolicy = ContextPolicy.GLOBAL_FALLBACK;
      initial = first;
    } else {
      throw new IllegalArgumentError('expected a ContextPolicy and/or an iterable of permission rules');
    }
    if (initial !== undefined) {
      if (!isIterable(initial) || typeof initial === 'string') {
        throw new IllegalArgumentError('initialPermissions must be an iterable of permission rules');
      }
      for (const rule of initial) {
        this.grant(rule);
      }
    }
  }

  hasPermission(node: string | PermissionNode, context?: string | null): boolean {
    return this.#contextPolicy.permits(this.#grants.values(), nameOf(node), context);
  }

  /**
   * Explains {@link hasPermission} through `ContextPolicy.explain`, with
   * `COMPLETE` provenance: the deciding layer and every applicable grant
   * covering the node.
   *
   * The grants only explain the answer if `hasPermission` is this class's
   * own. A subclass that overrides `hasPermission` gets an explanation of
   * that override's answer with `UNAVAILABLE` provenance, never the
   * grants' answer; to report the grants when the override does not change
   * the answer (one that only audits checks, say), override this method to
   * return `this.contextPolicy.explain(this.grants(), node, context)`.
   */
  explain(node: string | PermissionNode, context?: string | null): PermissionExplanation {
    const name = nameOf(node);
    if (this.hasPermission !== MemoryPermissionSubject.prototype.hasPermission) {
      const requested = PermissionGrant.requireValidContext(context);
      return PermissionExplanation.unavailable(name, requested, checkSubject(this, name, requested));
    }
    return this.#contextPolicy.explain(this.#grants.values(), name, context);
  }

  grant(rule: string | PermissionNode, context?: string | null): void {
    const grant = new PermissionGrant(nameOf(rule), context);
    this.#grants.set(keyOf(grant), grant);
  }

  revoke(rule: string | PermissionNode, context?: string | null): void {
    this.#grants.delete(keyOf(new PermissionGrant(nameOf(rule), context)));
  }

  /**
   * Every grant this subject holds, deny rules and every context
   * included, in the order they were first granted. A snapshot: later
   * changes to the subject do not show up in it.
   */
  grants(): readonly PermissionGrant[] {
    return Object.freeze([...this.#grants.values()]);
  }

  /** The policy deciding which grants apply in a context. */
  get contextPolicy(): ContextPolicy {
    return this.#contextPolicy;
  }
}

function nameOf(value: string | PermissionNode): string {
  return value instanceof PermissionNode ? value.name : value;
}

/** A rule cannot contain a space, so the two parts cannot run into each other. */
function keyOf(grant: PermissionGrant): string {
  return grant.context === null ? grant.rule : `${grant.rule} ${grant.context}`;
}

function isIterable(value: unknown): value is Iterable<string> {
  return (
    value !== null &&
    value !== undefined &&
    typeof (value as { [Symbol.iterator]?: unknown })[Symbol.iterator] === 'function'
  );
}
