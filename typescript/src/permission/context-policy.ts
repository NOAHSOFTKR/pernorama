import { IllegalArgumentError } from '../error/errors.js';
import { Decision } from './decision.js';
import { PermissionExplanation, type RankedGrant } from './permission-explanation.js';
import { PermissionGrant } from './permission-grant.js';
import { decisionOf, NOT_COVERING, rank, validateNode } from './syntax.js';

const INTERNAL = Symbol('ContextPolicy');

/**
 * Decides which {@link PermissionGrant grants} apply when a permission is
 * checked in a context, and in what order. It is the only place contexts
 * are interpreted; `PermissionResolver` keeps deciding between rules
 * exactly as it always has, and never sees a context.
 *
 * The policy is chosen once, for a whole `Pernorama` instance — individual
 * permissions do not carry their own. Both policies treat a check
 * **without** a context the same way: only grants without a context apply.
 * They differ in what a check **with** a context sees.
 *
 * ## `ContextPolicy.GLOBAL_FALLBACK`
 * A grant without a context is global: it applies in every context,
 * underneath the grants made for that context. Checking `node` in
 * `academy:123` goes through two layers:
 *
 * 1. the grants scoped to `academy:123`. If any of their rules — allow or
 *    deny — covers `node`, they decide, with the usual precedence among
 *    themselves;
 * 2. only if none of them covers it, the grants without a context decide.
 *
 * So a context overrides the global grants for every node it says anything
 * about, even with a less specific rule:
 *
 * ```
 * students.delete               // global allow
 * -students.*   @ academy:123   // contextual deny
 *
 * students.delete @ academy:123 -> denied  (the context covers it)
 * students.delete @ academy:456 -> allowed (falls back to the global grant)
 * ```
 *
 * and the reverse also holds: a context that grants `students.*` permits
 * `students.delete` there even if a global rule denies it.
 *
 * ## `ContextPolicy.EXACT`
 * Grants with and without a context are separate. A check in `academy:123`
 * sees only the grants scoped to exactly `academy:123`; a global grant
 * does not reach into any context.
 *
 * ## Matching contexts
 * Two contexts match only if they are equal strings. No context value has
 * special meaning: `"academy:*"` is not a wildcard and `"academy"` is not a
 * parent of `"academy:123"`.
 *
 * There are exactly two instances, so policies compare with `===`.
 */
export class ContextPolicy {
  /**
   * Grants without a context apply in every context, underneath the grants
   * scoped to the context being checked.
   */
  static readonly GLOBAL_FALLBACK: ContextPolicy = new ContextPolicy(INTERNAL, 'GLOBAL_FALLBACK', true);

  /**
   * Only grants scoped to exactly the context being checked apply; a grant
   * without a context applies only to a check without one.
   */
  static readonly EXACT: ContextPolicy = new ContextPolicy(INTERNAL, 'EXACT', false);

  /** `"GLOBAL_FALLBACK"` or `"EXACT"`. */
  readonly name: 'GLOBAL_FALLBACK' | 'EXACT';
  readonly #fallsBackToGlobal: boolean;

  private constructor(token: symbol, name: 'GLOBAL_FALLBACK' | 'EXACT', fallsBackToGlobal: boolean) {
    if (token !== INTERNAL) {
      // `private` is only a compile-time promise; policies are compared by identity
      throw new TypeError('ContextPolicy cannot be constructed; use ContextPolicy.GLOBAL_FALLBACK or ContextPolicy.EXACT');
    }
    this.name = name;
    this.#fallsBackToGlobal = fallsBackToGlobal;
    Object.freeze(this);
  }

  /**
   * The policy with the given {@link name}.
   *
   * @throws IllegalArgumentError if there is no such policy
   */
  static valueOf(name: string): ContextPolicy {
    if (name === 'GLOBAL_FALLBACK') {
      return ContextPolicy.GLOBAL_FALLBACK;
    }
    if (name === 'EXACT') {
      return ContextPolicy.EXACT;
    }
    throw new IllegalArgumentError(`No context policy named '${String(name)}'`);
  }

  /**
   * Returns `true` if something granted in `grantedContext` applies to a
   * check in `requestedContext` — whether it can take part in the decision
   * at all, not whether it wins it. Used to decide which held roles count
   * for a check; see {@link permits} for evaluating rules.
   *
   * @throws IllegalArgumentError if either context is empty
   */
  applies(grantedContext: string | null | undefined, requestedContext: string | null | undefined): boolean {
    const granted = PermissionGrant.requireValidContext(grantedContext);
    const requested = PermissionGrant.requireValidContext(requestedContext);
    return granted === requested || this.#fallsBackTo(granted);
  }

  /**
   * Returns `true` if `grants` permit `node` in `context` (`null` for a
   * check without one), applying this policy to pick the grants that apply
   * and `PermissionResolver`'s precedence among their rules. A node no
   * applicable rule covers is not permitted.
   *
   * This is what `MemoryPermissionSubject` calls, and what a custom
   * subject storing grants with contexts should call too.
   *
   * @throws InvalidPermissionException if `node` is not a valid node
   * @throws IllegalArgumentError if `context` is empty
   */
  permits(grants: Iterable<PermissionGrant>, node: string, context?: string | null): boolean {
    return this.#evaluate(grants, node, context, null) === Decision.PERMITTED;
  }

  /**
   * {@link permits}, also reporting why: the three-way decision, which
   * layer decided, and every applicable grant whose rule covers `node`,
   * the deciding ones marked. Its `allowed` is always what `permits`
   * returns for the same arguments — both run the same evaluation.
   *
   * @throws InvalidPermissionException if `node` is not a valid node
   * @throws IllegalArgumentError if `context` is empty
   */
  explain(grants: Iterable<PermissionGrant>, node: string, context?: string | null): PermissionExplanation {
    const covering: RankedGrant[] = [];
    const decision = this.#evaluate(grants, node, context, covering);
    return PermissionExplanation._ofRules(node, context ?? null, decision, this, covering);
  }

  /**
   * The one evaluation behind {@link permits} and {@link explain}: adds
   * every applicable grant covering `node` to `covering` unless it is
   * `null`, which is the plain check.
   */
  #evaluate(
    grants: Iterable<PermissionGrant>,
    node: string,
    context: string | null | undefined,
    covering: RankedGrant[] | null,
  ): Decision {
    if (grants === null || grants === undefined) {
      throw new IllegalArgumentError('grants must not be null');
    }
    const requested = PermissionGrant.requireValidContext(context);
    validateNode(node);

    // One pass, ranking the scoped and the global layer side by side.
    // A PermissionGrant validated its rule when it was created.
    let scoped = NOT_COVERING;
    let global = NOT_COVERING;
    for (const grant of grants) {
      if (!(grant instanceof PermissionGrant)) {
        throw new IllegalArgumentError('grants must contain only PermissionGrant instances');
      }
      let fallback: boolean;
      if (grant.context === requested) {
        fallback = false;
      } else if (this.#fallsBackTo(grant.context)) {
        fallback = true;
      } else {
        continue;
      }
      const ranked = rank(grant.rule, node);
      if (fallback) {
        global = Math.max(global, ranked);
      } else {
        scoped = Math.max(scoped, ranked);
      }
      if (covering !== null && ranked !== NOT_COVERING) {
        covering.push({ grant, fallback, rank: ranked });
      }
    }

    const decision = decisionOf(scoped);
    return decision === Decision.NOT_COVERED ? decisionOf(global) : decision;
  }

  /**
   * Whether something granted in `grantedContext` reaches a check in a
   * different context: only a global grant does, and only under a policy
   * that falls back to global grants.
   */
  #fallsBackTo(grantedContext: string | null): boolean {
    return this.#fallsBackToGlobal && grantedContext === null;
  }

  toString(): string {
    return this.name;
  }

  toJSON(): string {
    return this.name;
  }
}
