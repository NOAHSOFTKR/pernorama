import { IllegalStateError } from '../error/errors.js';
import type { ContextPolicy } from '../permission/context-policy.js';
import { Decision } from '../permission/decision.js';
import { Contribution, Layer, PermissionExplanation, Provenance } from '../permission/permission-explanation.js';
import type { RoleAssignment } from './role-assignment.js';

/**
 * Decides whether a target is permitted a node, given the role assignments
 * that apply to the check. Each role still answers for itself — through
 * `Role.permissions` and `Role.denies`, which use the core's matching
 * rules — and a policy only combines those answers.
 *
 * Which assignments apply is settled before the policy is called:
 * `RoleAssignments` passes only those whose context its `ContextPolicy`
 * applies to the context being checked. A role carries no context of its
 * own, so each one is asked without a context.
 *
 * ## Context first
 * Under `ContextPolicy.GLOBAL_FALLBACK` a check in a context can see roles
 * held in that context and roles held without one. The built-in policies
 * treat them as two layers, exactly as `ContextPolicy.permits` treats
 * grants: if any role held in the checked context permits or explicitly
 * denies the node, those roles decide, and the roles held without a
 * context decide only otherwise. So a role held in `academy:123` can
 * narrow, or re-allow, what a global role says about a node, in
 * `academy:123` only. A check without a context, or one under
 * `ContextPolicy.EXACT`, has a single layer.
 *
 * Which roles a target may hold together is a separate question, answered
 * by `RoleAssignmentPolicy`.
 *
 * Implement this interface for a combination the built-in policies do not
 * cover — one that ranks roles by their group, say. A custom policy
 * receives every applicable assignment, from both layers, and decides for
 * itself how they relate. The node and context passed in have already been
 * validated. It must answer with a boolean, synchronously.
 *
 * Explaining a check through a built-in policy reports the deciding layer
 * and the roles that decided it. A custom policy only returns its answer,
 * so the explanation lists the applicable roles, each with its own
 * explanation, with `PARTIAL` provenance — `UNAVAILABLE` if no role could
 * be explained — and none of them marked decisive.
 */
export interface PermissionResolutionPolicy {
  /**
   * Returns whether `assignments`, taken together, permit `node` in
   * `context`.
   *
   * @param assignments the target's assignments that apply to `context`,
   *                    oldest first
   * @param node        a valid permission node
   * @param context     the context being checked, or `null` for none
   */
  hasPermission(assignments: readonly RoleAssignment[], node: string, context: string | null): boolean;
}

/** The built-in policies. Compare with `===`. */
export const PermissionResolutionPolicy: {
  /**
   * Permitted if **any** role in the deciding layer permits the node. A
   * deny rule only limits the role holding it within its layer, which is
   * exactly how `CompositePermissionSubject` combines its sources; across
   * layers, a role held in the checked context that denies the node still
   * decides it. This is the default for `RoleAssignments.subject`.
   */
  readonly ALLOW_OVERRIDES: PermissionResolutionPolicy;
  /**
   * Permitted if some role in the deciding layer permits the node and
   * **no** role in it explicitly denies it: a deny rule in one role vetoes
   * a grant in another held in the same layer. A role held in the checked
   * context therefore outranks a role held without one, in either
   * direction. A role that simply does not mention the node does not veto
   * anything, and only a role built from rules can deny.
   */
  readonly DENY_OVERRIDES: PermissionResolutionPolicy;
} = Object.freeze({
  ALLOW_OVERRIDES: Object.freeze({
    hasPermission: (assignments: readonly RoleAssignment[], node: string, context: string | null) =>
      layered(assignments, node, context, false, null) === Decision.PERMITTED,
  }),
  DENY_OVERRIDES: Object.freeze({
    hasPermission: (assignments: readonly RoleAssignment[], node: string, context: string | null) =>
      layered(assignments, node, context, true, null) === Decision.PERMITTED,
  }),
});

/**
 * Decides the layer of roles held in exactly `context` first, and the
 * rest — the roles held without a context that apply to it — only if the
 * first layer does not cover `node`.
 *
 * @param explained where to explain each role it consults, for an
 *                  explanation; `null` for the plain check
 */
function layered(
  assignments: readonly RoleAssignment[],
  node: string,
  context: string | null,
  denyOverrides: boolean,
  explained: Explained | null,
): Decision {
  const decision = decideLayer(assignments, node, context, true, denyOverrides, explained);
  if (decision === Decision.NOT_COVERED) {
    return decideLayer(assignments, node, context, false, denyOverrides, explained);
  }
  return decision;
}

/**
 * The decision of one layer: the assignments held in `context` if
 * `scoped`, otherwise those held without a context. An assignment held in
 * some other context belongs to neither, even if a caller passes one in.
 * Under `denyOverrides` any denial decides the layer; otherwise any
 * permission does. A layer in which no role covers the node is
 * `NOT_COVERED`.
 */
function decideLayer(
  assignments: readonly RoleAssignment[],
  node: string,
  context: string | null,
  scoped: boolean,
  denyOverrides: boolean,
  explained: Explained | null,
): Decision {
  let permitted = false;
  let denied = false;
  for (let i = 0; i < assignments.length; i++) {
    const assignment = assignments[i]!;
    if (!inLayer(assignment, context, scoped)) {
      continue;
    }
    const decision = explained === null ? assignment.role._decide(node) : explained.decision(i);
    if (decision === Decision.PERMITTED) {
      if (!denyOverrides) {
        return Decision.PERMITTED;
      }
      permitted = true;
    } else if (decision === Decision.DENIED) {
      if (denyOverrides) {
        return Decision.DENIED;
      }
      denied = true;
    }
  }
  if (permitted) {
    return Decision.PERMITTED;
  }
  return denied ? Decision.DENIED : Decision.NOT_COVERED;
}

function inLayer(assignment: RoleAssignment, context: string | null, scoped: boolean): boolean {
  const inContext = assignment.context === context;
  return scoped ? inContext : !inContext && assignment.context === null;
}

/**
 * What `policy` answers for `applicable`, required to be a boolean: a
 * custom policy that returns a `Promise` must not read as "permitted".
 *
 * @internal
 */
export function resolve(
  policy: PermissionResolutionPolicy,
  applicable: readonly RoleAssignment[],
  node: string,
  context: string | null,
): boolean {
  const answer: unknown = policy.hasPermission(applicable, node, context);
  if (answer !== true && answer !== false) {
    throw new IllegalStateError('a PermissionResolutionPolicy must return a boolean synchronously');
  }
  return answer;
}

/**
 * Explains what `policy` answers for `applicable`, the assignments
 * `contextPolicy` applies to `context`.
 *
 * The roles the check itself consults are consulted the same way and in
 * the same order — for a built-in policy through {@link layered} itself,
 * which stops where the check stops — and an error from one of them
 * propagates, as it would from the check. Every other applicable role is
 * then explained only to be reported: one that throws is left out of the
 * contributions and the provenance becomes `PARTIAL`, since it could not
 * have changed the answer. A custom policy is asked for its answer first;
 * how it combined the roles is not known, so every role is reported, none
 * of them decisive.
 *
 * @internal
 */
export function explainResolution(
  applicable: readonly RoleAssignment[],
  node: string,
  context: string | null,
  policy: PermissionResolutionPolicy,
  contextPolicy: ContextPolicy,
): PermissionExplanation {
  const explained = new Explained(applicable, node);
  const builtIn =
    policy === PermissionResolutionPolicy.ALLOW_OVERRIDES || policy === PermissionResolutionPolicy.DENY_OVERRIDES;

  if (!builtIn) {
    const allowed = resolve(policy, applicable, node, context);
    explained.observeRest();
    const builder = PermissionExplanation.builder(node, context, allowed)
      .contextPolicy(contextPolicy)
      .provenance(explained.anyReported() ? Provenance.PARTIAL : Provenance.UNAVAILABLE);
    applicable.forEach((assignment, i) => {
      const explanation = explained.explanation(i);
      if (explanation !== null) {
        builder.contribution(new Contribution(assignment, false, explanation));
      }
    });
    return builder.build();
  }

  const denyOverrides = policy === PermissionResolutionPolicy.DENY_OVERRIDES;
  const decision = layered(applicable, node, context, denyOverrides, explained);
  // re-walks only roles layered already consulted, so nothing new is evaluated
  let layer: Layer | null = null;
  if (decideLayer(applicable, node, context, true, denyOverrides, explained) !== Decision.NOT_COVERED) {
    layer = Layer.EXACT_CONTEXT;
  } else if (decision !== Decision.NOT_COVERED) {
    layer = Layer.GLOBAL_FALLBACK;
  }
  explained.observeRest();

  const builder = PermissionExplanation.builder(node, context, decision === Decision.PERMITTED)
    .decision(decision)
    .provenance(explained.allComplete() ? Provenance.COMPLETE : Provenance.PARTIAL)
    .contextPolicy(contextPolicy)
    .resolutionPolicy(denyOverrides ? 'DENY_OVERRIDES' : 'ALLOW_OVERRIDES')
    .decidingLayer(layer);
  applicable.forEach((assignment, i) => {
    const explanation = explained.explanation(i);
    if (explanation === null) {
      return;
    }
    const decisive =
      layer !== null &&
      inLayer(assignment, context, layer === Layer.EXACT_CONTEXT) &&
      explained.decision(i) === decision;
    builder.contribution(new Contribution(assignment, decisive, explanation));
  });
  return builder.build();
}

/**
 * Each applicable role's explanation, made when first needed: by the
 * evaluation itself, through {@link Explained.decision}, or afterwards, by
 * {@link Explained.observeRest}. A role is asked at most once.
 */
class Explained {
  readonly #assignments: readonly RoleAssignment[];
  readonly #node: string;
  readonly #explanations: (PermissionExplanation | null)[];
  readonly #failed: boolean[];

  constructor(assignments: readonly RoleAssignment[], node: string) {
    this.#assignments = assignments;
    this.#node = node;
    this.#explanations = assignments.map(() => null);
    this.#failed = assignments.map(() => false);
  }

  /** The decision of role `i`, explaining it now if needed; an error propagates. */
  decision(i: number): Decision {
    const role = this.#assignments[i]!.role;
    const explanation = (this.#explanations[i] ??= role._explain(this.#node));
    return role._decisionOf(explanation);
  }

  /** Explains every role not consulted yet, leaving out any that throws. */
  observeRest(): void {
    for (let i = 0; i < this.#explanations.length; i++) {
      if (this.#explanations[i] === null) {
        try {
          this.#explanations[i] = this.#assignments[i]!.role._explain(this.#node);
        } catch {
          this.#failed[i] = true;
        }
      }
    }
  }

  explanation(i: number): PermissionExplanation | null {
    return this.#explanations[i] ?? null;
  }

  anyReported(): boolean {
    return this.#explanations.some((explanation) => explanation !== null);
  }

  /** Whether every role was explained, each completely. */
  allComplete(): boolean {
    return this.#explanations.every(
      (explanation, i) => !this.#failed[i] && explanation?.provenance === Provenance.COMPLETE,
    );
  }
}
