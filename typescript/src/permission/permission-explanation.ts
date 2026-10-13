import { IllegalArgumentError, IllegalStateError } from '../error/errors.js';
import type { ContextPolicy } from './context-policy.js';
import { Decision } from './decision.js';
import { PermissionGrant } from './permission-grant.js';
import { isDeny, NOT_COVERING, validateNode } from './syntax.js';

/**
 * Which grants (or role assignments) decided a check, when a
 * `ContextPolicy` put them in layers.
 */
export const Layer = {
  /**
   * Those held in exactly the checked context — for a check without a
   * context, those held without one.
   */
  EXACT_CONTEXT: 'EXACT_CONTEXT',
  /**
   * Those held without a context, reached from a check in a context
   * because `ContextPolicy.GLOBAL_FALLBACK` falls back to them when nothing
   * held in the context covers the node.
   */
  GLOBAL_FALLBACK: 'GLOBAL_FALLBACK',
} as const;

export type Layer = (typeof Layer)[keyof typeof Layer];

/** How much of the reason for an answer an explanation reports. */
export const Provenance = {
  /** The decision and every rule and source behind it are reported. */
  COMPLETE: 'COMPLETE',
  /**
   * Part of the reason is reported — some source only gave its answer, or
   * the way sources were combined is not known.
   */
  PARTIAL: 'PARTIAL',
  /** Only the answer is known; nothing about why. */
  UNAVAILABLE: 'UNAVAILABLE',
} as const;

export type Provenance = (typeof Provenance)[keyof typeof Provenance];

/** One applicable grant whose rule covers the checked node. */
export class RuleMatch {
  /** The grant, with the context it is held in. */
  readonly grant: PermissionGrant;
  /**
   * Whether this rule decided the answer: the most specific covering rule
   * of the deciding layer, a deny rule winning a tie.
   */
  readonly decisive: boolean;

  constructor(grant: PermissionGrant, decisive: boolean) {
    if (!(grant instanceof PermissionGrant)) {
      throw new IllegalArgumentError('grant must be a PermissionGrant');
    }
    this.grant = grant;
    this.decisive = decisive === true;
    Object.freeze(this);
  }

  /** Whether the rule is a deny rule. */
  get deny(): boolean {
    return isDeny(this.grant.rule);
  }

  /** Whether the rule ends in a wildcard (`"users.*"`, `"*"`). */
  get wildcard(): boolean {
    return this.grant.rule.endsWith('*');
  }

  toString(): string {
    return this.decisive ? `${this.grant} (decisive)` : this.grant.toString();
  }
}

/**
 * One source a combining subject consulted, with that source's own
 * explanation.
 */
export class Contribution {
  /**
   * What was consulted: the `PermissionSubject` for a composite, the
   * `RoleAssignment` for a role-assignment subject. The live object, not a
   * copy.
   */
  readonly source: object;
  /**
   * Whether this source's answer decided the combined answer; `false` for
   * every source when how they were combined is not known.
   */
  readonly decisive: boolean;
  /** The source's own explanation. */
  readonly explanation: PermissionExplanation;

  constructor(source: object, decisive: boolean, explanation: PermissionExplanation) {
    if (source === null || source === undefined) {
      throw new IllegalArgumentError('source must not be null');
    }
    if (!(explanation instanceof PermissionExplanation)) {
      throw new IllegalArgumentError('explanation must be a PermissionExplanation');
    }
    this.source = source;
    this.decisive = decisive === true;
    this.explanation = explanation;
    Object.freeze(this);
  }

  toString(): string {
    return `${String(this.source)}${this.decisive ? ' (decisive)' : ''}: ${this.explanation}`;
  }
}

/**
 * A grant that covers the node being explained, with its rank and whether
 * it was reached by falling back to the global grants. Collected while a
 * check is evaluated, so an explanation is built from the very ranks that
 * decided it rather than from a second evaluation.
 *
 * @internal
 */
export interface RankedGrant {
  readonly grant: PermissionGrant;
  readonly fallback: boolean;
  readonly rank: number;
}

interface BuilderState {
  readonly node: string;
  readonly context: string | null;
  readonly allowed: boolean;
  decision: Decision | null;
  provenance: Provenance;
  contextPolicy: ContextPolicy | null;
  resolutionPolicy: string | null;
  decidingLayer: Layer | null;
  readonly matches: RuleMatch[];
  readonly contributions: Contribution[];
}

/**
 * Why a permission check came out the way it did: what was checked, the
 * answer, and — as far as the answering subject can tell — the rules,
 * context layer and sources that decided it.
 *
 * ```ts
 * const explanation = user.explain('students.delete', 'academy:123');
 *
 * explanation.allowed;       // false
 * explanation.decision;      // 'DENIED'
 * explanation.decidingLayer; // 'EXACT_CONTEXT'
 * explanation.matches;       // [-students.* @ academy:123 (decisive), students.delete]
 * ```
 *
 * Its {@link allowed} is always the answer `hasPermission` gives for the
 * same node and context; everything else describes how that answer was
 * reached.
 *
 * ## Decision
 * {@link decision} keeps apart what {@link allowed} folds together:
 * `DENIED` when a deny rule (or a denying source) decided the node, and
 * `NOT_COVERED` when nothing covered it at all. Both mean
 * `allowed === false`. It is `null` when the subject only says "not
 * allowed" without saying which — a custom subject that does not implement
 * `explain`, for instance.
 *
 * ## Provenance
 * An explanation never reports a reason it could not determine.
 * {@link provenance} says how much of the reason is known: `COMPLETE` when
 * every rule and source behind the answer is reported, `PARTIAL` when some
 * of it is, and `UNAVAILABLE` when only the answer is.
 *
 * ## Who may see one
 * An explanation is diagnostic information about how a subject's
 * permissions are configured — the grants, roles and contexts it holds.
 * Log it, or show it to administrators; do not hand it unfiltered to the
 * end user whose request was denied, which would tell them exactly what
 * they lack and where it is granted.
 *
 * Immutable, except that a {@link Contribution.source} is the live subject
 * or assignment that was consulted, not a copy of it.
 */
export class PermissionExplanation {
  /** The node that was checked. */
  readonly node: string;
  /** The context the node was checked in, or `null` for none. */
  readonly context: string | null;
  /** The answer: what `hasPermission` returns for the same node and context. */
  readonly allowed: boolean;
  /**
   * `PERMITTED` if allowed; otherwise `DENIED` or `NOT_COVERED` if the
   * subject can tell which, and `null` if it cannot.
   */
  readonly decision: Decision | null;
  /** How much of the reason for the answer this explanation reports. */
  readonly provenance: Provenance;
  /** The context policy that put grants or role assignments in layers, if one did. */
  readonly contextPolicy: ContextPolicy | null;
  /**
   * How {@link contributions} were combined, if that is known:
   * `"ANY_SOURCE"` for a `CompositePermissionSubject`, and
   * `"ALLOW_OVERRIDES"` or `"DENY_OVERRIDES"` for a role-assignment
   * subject using that built-in policy. `null` for a custom policy, and for
   * a subject that does not combine sources.
   */
  readonly resolutionPolicy: string | null;
  /**
   * Which layer decided, when a `ContextPolicy` put grants or role
   * assignments in layers and one of them covered the node. `null` when
   * nothing covered it, and for a plain rule set, which has no layers.
   */
  readonly decidingLayer: Layer | null;
  /**
   * Every applicable grant whose rule covers the node, in precedence
   * order: the grants held in the checked context before those reached by
   * falling back to global grants, and within each, the more specific
   * rule — and on a tie, the deny rule — first. Grants that do not cover
   * the node, or that do not apply to the checked context, are left out.
   * Empty for a subject that does not hold grants itself.
   */
  readonly matches: readonly RuleMatch[];
  /**
   * The sources a combining subject consulted, in the order it holds them,
   * each with its own explanation. Empty for a subject that does not
   * combine sources.
   */
  readonly contributions: readonly Contribution[];

  private constructor(state: BuilderState) {
    this.node = state.node;
    this.context = state.context;
    this.allowed = state.allowed;
    this.decision = state.allowed ? Decision.PERMITTED : state.decision;
    this.provenance = state.provenance;
    this.contextPolicy = state.contextPolicy;
    this.resolutionPolicy = state.resolutionPolicy;
    this.decidingLayer = state.decidingLayer;
    this.matches = Object.freeze([...state.matches]);
    this.contributions = Object.freeze([...state.contributions]);
    Object.freeze(this);
  }

  /**
   * An explanation that reports only the answer, with `UNAVAILABLE`
   * provenance: what a subject that does not implement `explain` gets.
   *
   * @throws InvalidPermissionException if `node` is not a valid node
   * @throws IllegalArgumentError if `context` is empty, or `allowed` is
   *         not a boolean
   */
  static unavailable(node: string, context: string | null | undefined, allowed: boolean): PermissionExplanation {
    return PermissionExplanation.builder(node, context, allowed).build();
  }

  /**
   * Starts building an explanation, for a custom subject or resolution
   * policy that can report more than its answer. Every property but the
   * answer is optional, and the provenance defaults to `UNAVAILABLE`:
   * report what you know, and claim `COMPLETE` only if it is everything.
   *
   * @throws InvalidPermissionException if `node` is not a valid node
   * @throws IllegalArgumentError if `context` is empty, or `allowed` is
   *         not a boolean
   */
  static builder(node: string, context: string | null | undefined, allowed: boolean): PermissionExplanationBuilder {
    validateNode(node);
    const validContext = PermissionGrant.requireValidContext(context);
    if (typeof allowed !== 'boolean') {
      // a truthy non-boolean (a Promise, say) must never read as "allowed"
      throw new IllegalArgumentError('allowed must be a boolean');
    }
    return new PermissionExplanationBuilder(
      {
        node,
        context: validContext,
        allowed,
        decision: null,
        provenance: Provenance.UNAVAILABLE,
        contextPolicy: null,
        resolutionPolicy: null,
        decidingLayer: null,
        matches: [],
        contributions: [],
      },
      (state) => new PermissionExplanation(state),
    );
  }

  /**
   * The explanation of a set of rules, given every applicable grant that
   * covers `node` with its rank. `contextPolicy` is the policy that put
   * them in layers, or `null` for a plain rule set with no contexts, which
   * has no layers.
   *
   * @internal
   */
  static _ofRules(
    node: string,
    context: string | null,
    decision: Decision,
    contextPolicy: ContextPolicy | null,
    covering: readonly RankedGrant[],
  ): PermissionExplanation {
    // The scoped layer decides whenever it covers the node at all.
    let scopedCovers = false;
    let scopedBest = NOT_COVERING;
    let globalBest = NOT_COVERING;
    for (const ranked of covering) {
      if (ranked.fallback) {
        globalBest = Math.max(globalBest, ranked.rank);
      } else {
        scopedCovers = true;
        scopedBest = Math.max(scopedBest, ranked.rank);
      }
    }
    const decidingIsFallback = !scopedCovers;
    const decidingBest = scopedCovers ? scopedBest : globalBest;

    // Array.prototype.sort is stable, as List.sort is
    const ordered = [...covering].sort(
      (a, b) => Number(a.fallback) - Number(b.fallback) || b.rank - a.rank,
    );

    const builder = PermissionExplanation.builder(node, context, decision === Decision.PERMITTED)
      .decision(decision)
      .provenance(Provenance.COMPLETE)
      .contextPolicy(contextPolicy);
    if (contextPolicy !== null && covering.length > 0) {
      builder.decidingLayer(decidingIsFallback ? Layer.GLOBAL_FALLBACK : Layer.EXACT_CONTEXT);
    }
    for (const ranked of ordered) {
      const decisive = ranked.fallback === decidingIsFallback && ranked.rank === decidingBest;
      builder.match(new RuleMatch(ranked.grant, decisive));
    }
    return builder.build();
  }

  toString(): string {
    let s = `PermissionExplanation[node=${this.node}`;
    if (this.context !== null) {
      s += `, context=${this.context}`;
    }
    s += `, allowed=${this.allowed}`;
    if (this.decision !== null) {
      s += `, decision=${this.decision}`;
    }
    s += `, provenance=${this.provenance}`;
    if (this.contextPolicy !== null) {
      s += `, contextPolicy=${this.contextPolicy}`;
    }
    if (this.resolutionPolicy !== null) {
      s += `, resolutionPolicy=${this.resolutionPolicy}`;
    }
    if (this.decidingLayer !== null) {
      s += `, decidingLayer=${this.decidingLayer}`;
    }
    if (this.matches.length > 0) {
      s += `, matches=[${this.matches.join(', ')}]`;
    }
    if (this.contributions.length > 0) {
      s += `, contributions=[${this.contributions.join(', ')}]`;
    }
    return `${s}]`;
  }
}

/** Builder for {@link PermissionExplanation}; get one from `PermissionExplanation.builder`. */
export class PermissionExplanationBuilder {
  readonly #state: BuilderState;
  readonly #create: (state: BuilderState) => PermissionExplanation;

  /** @internal */
  constructor(state: BuilderState, create: (state: BuilderState) => PermissionExplanation) {
    this.#state = state;
    this.#create = create;
  }

  /**
   * Sets the three-way decision. It has to agree with the answer:
   * `PERMITTED` exactly when allowed. An allowed explanation is
   * `PERMITTED` without calling this.
   *
   * @throws IllegalArgumentError if `decision` contradicts the answer
   */
  decision(decision: Decision): this {
    if (decision !== Decision.PERMITTED && decision !== Decision.DENIED && decision !== Decision.NOT_COVERED) {
      throw new IllegalArgumentError(`unknown decision: ${String(decision)}`);
    }
    if ((decision === Decision.PERMITTED) !== this.#state.allowed) {
      throw new IllegalArgumentError(`decision ${decision} contradicts allowed=${this.#state.allowed}`);
    }
    this.#state.decision = decision;
    return this;
  }

  /** Sets how much of the reason is reported. Defaults to `UNAVAILABLE`. */
  provenance(provenance: Provenance): this {
    if (
      provenance !== Provenance.COMPLETE &&
      provenance !== Provenance.PARTIAL &&
      provenance !== Provenance.UNAVAILABLE
    ) {
      throw new IllegalArgumentError(`unknown provenance: ${String(provenance)}`);
    }
    this.#state.provenance = provenance;
    return this;
  }

  /** Sets the context policy that put grants or assignments in layers; `null` for none. */
  contextPolicy(contextPolicy: ContextPolicy | null): this {
    this.#state.contextPolicy = contextPolicy ?? null;
    return this;
  }

  /** Names how the contributions were combined; `null` if not known. */
  resolutionPolicy(resolutionPolicy: string | null): this {
    this.#state.resolutionPolicy = resolutionPolicy ?? null;
    return this;
  }

  /** Sets the layer that decided; `null` if none did. */
  decidingLayer(decidingLayer: Layer | null): this {
    this.#state.decidingLayer = decidingLayer ?? null;
    return this;
  }

  /** Adds a covering rule, in precedence order. */
  match(match: RuleMatch): this {
    if (!(match instanceof RuleMatch)) {
      throw new IllegalArgumentError('match must be a RuleMatch');
    }
    this.#state.matches.push(match);
    return this;
  }

  /** Adds a consulted source, in the order the subject holds them. */
  contribution(contribution: Contribution): this {
    if (!(contribution instanceof Contribution)) {
      throw new IllegalArgumentError('contribution must be a Contribution');
    }
    this.#state.contributions.push(contribution);
    return this;
  }

  /**
   * Builds the explanation.
   *
   * @throws IllegalStateError if the provenance is `COMPLETE` but a denied
   *         answer has no decision: a complete explanation knows whether
   *         the node was denied or not covered
   */
  build(): PermissionExplanation {
    const state = this.#state;
    if (state.provenance === Provenance.COMPLETE && !state.allowed && state.decision === null) {
      throw new IllegalStateError(
        'a complete explanation of a denied check needs its decision, DENIED or NOT_COVERED',
      );
    }
    return this.#create(state);
  }
}
