import { IllegalArgumentError, IllegalStateError, UnsupportedOperationError } from '../error/errors.js';
import { ContextPolicy } from '../permission/context-policy.js';
import type { PermissionExplanation } from '../permission/permission-explanation.js';
import { PermissionGrant } from '../permission/permission-grant.js';
import { validateNode } from '../permission/syntax.js';
import type { PermissionSubject } from '../subject/permission-subject.js';
import { explainResolution, PermissionResolutionPolicy, resolve } from './permission-resolution-policy.js';
import type { Role } from './role.js';
import { RoleAssignment, RoleAssignmentResult } from './role-assignment.js';
import { RoleAssignmentDecision } from './role-assignment-policy.js';
import {
  type AsyncRoleAssignmentStore,
  MemoryRoleAssignmentStore,
  type RoleAssignmentStore,
} from './role-assignment-store.js';
import type { RoleGroup } from './role-group.js';

/**
 * Assigns {@link Role}s to targets, optionally in a context, enforcing
 * each role's `RoleGroup` constraints, and answers permission checks from
 * the roles a target holds.
 *
 * ```ts
 * const assignments = pernorama.newRoleAssignments<string>();
 *
 * assignments.assign('alice', pro);                 // ASSIGNED
 * const result = assignments.assign('alice', max5); // REPLACED, if the group is exclusive
 *
 * const alice = assignments.subject('alice');
 * alice.hasPermission('app.plan.max5'); // true
 * ```
 *
 * ## Assigning
 * {@link assign} is idempotent: assigning a role the target already holds
 * in the same context returns `NO_CHANGE` and never consults a policy.
 * Otherwise, if the role's group is already at its maximum, the group's
 * `RoleAssignmentPolicy` decides whether to reject the assignment or which
 * held roles to replace. A role with no group is never limited.
 *
 * ## Contexts
 * Every operation takes an optional context, an opaque application-defined
 * string such as `"academy:123"`; `null` or an omitted argument means no
 * context. One target can hold the same role in several contexts, and each
 * context is counted on its own: a group's limits apply to the roles held
 * in one context, so a target can be a teacher in `academy:123` and a
 * student in `academy:456` even if the two roles share an exclusive group.
 * Assignments without a context are counted together, as one more context.
 * A group id still has one definition across every context: a held role
 * carrying a conflicting definition of the group fails the call wherever
 * it is held.
 *
 * Where an assignment applies is decided by the {@link ContextPolicy}
 * these assignments were created with, exactly as for a permission granted
 * in that context: under `GLOBAL_FALLBACK` a role assigned without a
 * context applies in every context, and under `EXACT` only to checks
 * without one. A role assigned in a context applies to checks in exactly
 * that context.
 *
 * ## Atomicity
 * Every call reads the target's assignments, works out the new list, and
 * writes it with one {@link RoleAssignmentStore.replace compare-and-set}.
 * A replacement is therefore a single change: the target is seen holding
 * either the old role or the new one, never neither. If something else
 * changed the target in between, the whole decision is made again from the
 * fresh state, so a policy may be consulted more than once.
 *
 * This class is synchronous and needs a synchronous store. For a store
 * that does I/O, use {@link AsyncRoleAssignments}.
 *
 * @typeParam K how a target is identified, e.g. a user id
 */
export class RoleAssignments<K> {
  readonly #store: RoleAssignmentStore<K>;
  readonly #contextPolicy: ContextPolicy;

  /**
   * Creates assignments kept in `store` — by default a new
   * {@link MemoryRoleAssignmentStore} — applying `contextPolicy`, by
   * default `ContextPolicy.GLOBAL_FALLBACK`. `pernorama.newRoleAssignments()`
   * uses your application's policy instead.
   */
  constructor(
    store: RoleAssignmentStore<K> = new MemoryRoleAssignmentStore<K>(),
    contextPolicy: ContextPolicy = ContextPolicy.GLOBAL_FALLBACK,
  ) {
    this.#store = requireStore(store);
    this.#contextPolicy = requireContextPolicy(contextPolicy);
  }

  /**
   * Assigns `role` to `target` in `context`, or without a context if it is
   * `null` or omitted. See the class documentation for how group limits
   * are applied.
   *
   * @returns `ASSIGNED`, `REPLACED`, `NO_CHANGE` or `REJECTED`
   * @throws IllegalArgumentError if `context` is empty
   * @throws IllegalStateError if the group's policy returned a decision
   *         that breaks the group's constraints, or a held role carries a
   *         conflicting definition of the same group id; nothing is
   *         changed in either case
   */
  assign(target: K, role: Role, context?: string | null): RoleAssignmentResult {
    requireTarget(target);
    const requested = new RoleAssignment(role, context);
    for (;;) {
      const current = this.#assignmentsOf(target);
      const plan = planAssign(current, requested);
      if (plan.updated === null) {
        return plan.result;
      }
      if (this.#replace(target, current, plan.updated)) {
        return plan.result;
      }
    }
  }

  /**
   * Removes `role` from `target` in `context`, or the assignment without a
   * context if it is `null` or omitted; the same role held in any other
   * context is untouched. Rejected if it would leave the target with fewer
   * roles in the group, in that context, than the group's minimum.
   *
   * @returns `UNASSIGNED`, `NO_CHANGE` (the role was not held in that
   *          context) or `REJECTED`
   * @throws IllegalArgumentError if `context` is empty
   * @throws IllegalStateError if `role` or a held role carries a
   *         conflicting definition of the same group id; nothing is changed
   */
  unassign(target: K, role: Role, context?: string | null): RoleAssignmentResult {
    requireTarget(target);
    const requested = new RoleAssignment(role, context);
    for (;;) {
      const current = this.#assignmentsOf(target);
      const plan = planUnassign(current, requested);
      if (plan.updated === null) {
        return plan.result;
      }
      if (this.#replace(target, current, plan.updated)) {
        return plan.result;
      }
    }
  }

  /**
   * The roles `target` holds in exactly `context` — or without a context,
   * if it is `null` or omitted — oldest assignment first. This is what is
   * held there, not what applies there: under `GLOBAL_FALLBACK`, roles
   * held without a context also apply in `context` but are not listed. Use
   * {@link assignments} for every role in every context.
   *
   * @throws IllegalArgumentError if `context` is empty
   */
  roles(target: K, context?: string | null): readonly Role[] {
    requireTarget(target);
    return rolesIn(this.#assignmentsOf(target), PermissionGrant.requireValidContext(context));
  }

  /** Every assignment `target` holds, in every context, oldest first. */
  assignments(target: K): readonly RoleAssignment[] {
    requireTarget(target);
    return this.#assignmentsOf(target);
  }

  /** The policy deciding where an assignment in a context applies. */
  get contextPolicy(): ContextPolicy {
    return this.#contextPolicy;
  }

  /**
   * A read-only {@link PermissionSubject} for `target`, combining with
   * `policy` — by default `PermissionResolutionPolicy.ALLOW_OVERRIDES`,
   * the same semantics as `CompositePermissionSubject` — the roles whose
   * assignments apply to the context being checked. The subject is a live
   * view: every `hasPermission` call reads the target's current
   * assignments, so it reflects later changes. `grant` and `revoke` throw
   * `UnsupportedOperationError`; change the assignments instead. To add
   * permissions granted to the target directly, compose this subject with
   * its own in a `CompositePermissionSubject`.
   */
  subject(
    target: K,
    policy: PermissionResolutionPolicy = PermissionResolutionPolicy.ALLOW_OVERRIDES,
  ): PermissionSubject {
    requireTarget(target);
    return new AssignedRolesSubject(
      () => this.#assignmentsOf(target),
      requirePolicy(policy),
      this.#contextPolicy,
      `RoleAssignments.subject(${String(target)})`,
    );
  }

  #assignmentsOf(target: K): readonly RoleAssignment[] {
    return snapshot(this.#store.assignments(target));
  }

  #replace(target: K, expected: readonly RoleAssignment[], updated: readonly RoleAssignment[]): boolean {
    return requireBoolean(this.#store.replace(target, expected, updated));
  }
}

/**
 * {@link RoleAssignments} over a store that answers asynchronously: the
 * same rules, limits, results and atomicity, with every operation
 * returning a `Promise`. Has no Java counterpart, where a store blocks.
 *
 * ```ts
 * const assignments = pernorama.newAsyncRoleAssignments(new PostgresRoleStore(pool));
 *
 * await assignments.assign(userId, teacher, 'academy:123');
 *
 * const subject = await assignments.subject(userId); // loads once
 * subject.hasPermission('students.read', 'academy:123'); // synchronous
 * ```
 *
 * ## Atomicity and concurrency
 * Each call reads, decides, and writes with the store's compare-and-set,
 * retrying from a fresh read when the write reports that the assignments
 * changed in between. Two concurrent `assign` calls for one target can
 * therefore never both be applied on top of the same state, and a group's
 * limits hold — provided the store's `replace` really is atomic; see
 * {@link AsyncRoleAssignmentStore}.
 *
 * ## Subjects are snapshots
 * {@link subject} reads the target's assignments once and returns a
 * subject that answers from that list, synchronously, as every
 * `PermissionSubject` does. It does not see later changes: load one per
 * request, or per unit of work, rather than keeping it around.
 *
 * @typeParam K how a target is identified, e.g. a user id
 */
export class AsyncRoleAssignments<K> {
  readonly #store: AsyncRoleAssignmentStore<K>;
  readonly #contextPolicy: ContextPolicy;

  /**
   * Creates assignments kept in `store`, applying `contextPolicy`, by
   * default `ContextPolicy.GLOBAL_FALLBACK`.
   * `pernorama.newAsyncRoleAssignments(store)` uses your application's
   * policy instead.
   */
  constructor(store: AsyncRoleAssignmentStore<K>, contextPolicy: ContextPolicy = ContextPolicy.GLOBAL_FALLBACK) {
    this.#store = requireStore(store);
    this.#contextPolicy = requireContextPolicy(contextPolicy);
  }

  /** {@link RoleAssignments.assign}, asynchronously. */
  async assign(target: K, role: Role, context?: string | null): Promise<RoleAssignmentResult> {
    requireTarget(target);
    const requested = new RoleAssignment(role, context);
    for (;;) {
      const current = await this.#assignmentsOf(target);
      const plan = planAssign(current, requested);
      if (plan.updated === null) {
        return plan.result;
      }
      if (requireBoolean(await this.#store.replace(target, current, plan.updated))) {
        return plan.result;
      }
    }
  }

  /** {@link RoleAssignments.unassign}, asynchronously. */
  async unassign(target: K, role: Role, context?: string | null): Promise<RoleAssignmentResult> {
    requireTarget(target);
    const requested = new RoleAssignment(role, context);
    for (;;) {
      const current = await this.#assignmentsOf(target);
      const plan = planUnassign(current, requested);
      if (plan.updated === null) {
        return plan.result;
      }
      if (requireBoolean(await this.#store.replace(target, current, plan.updated))) {
        return plan.result;
      }
    }
  }

  /** {@link RoleAssignments.roles}, asynchronously. */
  async roles(target: K, context?: string | null): Promise<readonly Role[]> {
    requireTarget(target);
    const requested = PermissionGrant.requireValidContext(context);
    return rolesIn(await this.#assignmentsOf(target), requested);
  }

  /** Every assignment `target` holds, in every context, oldest first. */
  async assignments(target: K): Promise<readonly RoleAssignment[]> {
    requireTarget(target);
    return this.#assignmentsOf(target);
  }

  /** The policy deciding where an assignment in a context applies. */
  get contextPolicy(): ContextPolicy {
    return this.#contextPolicy;
  }

  /**
   * Loads `target`'s assignments and returns a read-only
   * {@link PermissionSubject} that answers from them with `policy`, by
   * default `PermissionResolutionPolicy.ALLOW_OVERRIDES`. A snapshot, not
   * a live view; see the class documentation.
   */
  async subject(
    target: K,
    policy: PermissionResolutionPolicy = PermissionResolutionPolicy.ALLOW_OVERRIDES,
  ): Promise<PermissionSubject> {
    requireTarget(target);
    requirePolicy(policy);
    const loaded = await this.#assignmentsOf(target);
    return new AssignedRolesSubject(
      () => loaded,
      policy,
      this.#contextPolicy,
      `AsyncRoleAssignments.subject(${String(target)})`,
    );
  }

  async #assignmentsOf(target: K): Promise<readonly RoleAssignment[]> {
    return snapshot(await this.#store.assignments(target));
  }
}

/** What an assign or unassign call does: the result, and the list to write, or `null` to write nothing. */
interface Plan {
  readonly result: RoleAssignmentResult;
  readonly updated: readonly RoleAssignment[] | null;
}

function planAssign(current: readonly RoleAssignment[], requested: RoleAssignment): Plan {
  const { role, context } = requested;
  if (current.some((existing) => existing.equals(requested))) {
    return { result: RoleAssignmentResult._noChange(role, context, true), updated: null };
  }

  let removed: readonly Role[] = [];
  const group = role.group;
  if (group !== null) {
    const held = heldIn(current, group, context);
    if (held.length >= group.maxAssignments) {
      const decision: unknown = group.assignmentPolicy.decide(group, held, role);
      if (!(decision instanceof RoleAssignmentDecision)) {
        throw new IllegalStateError(
          `assignment policy of group '${group.id}' did not return a RoleAssignmentDecision`,
        );
      }
      if (decision.rejectionReason !== null) {
        return {
          result: RoleAssignmentResult._rejected(role, context, false, decision.rejectionReason),
          updated: null,
        };
      }
      removed = decision.replacedRoles;
      checkReplacement(group, held, removed);
    }
  }

  const updated = current.filter(
    (existing) => !(existing.context === context && removed.some((gone) => gone.equals(existing.role))),
  );
  updated.push(requested);
  return {
    result:
      removed.length === 0
        ? RoleAssignmentResult._assigned(role, context)
        : RoleAssignmentResult._replaced(role, context, removed),
    updated: Object.freeze(updated),
  };
}

function planUnassign(current: readonly RoleAssignment[], requested: RoleAssignment): Plan {
  const { role, context } = requested;
  const index = current.findIndex((existing) => existing.equals(requested));
  if (index < 0) {
    return { result: RoleAssignmentResult._noChange(role, context, false), updated: null };
  }

  // the stored role is the one whose group the target was counted against
  const group = current[index]!.role.group;
  const requestedGroup = role.group;
  if (group !== null && requestedGroup !== null && group.equals(requestedGroup)) {
    requireSameDefinition(group, requestedGroup, role);
  }
  if (group !== null) {
    const remaining = heldIn(current, group, context).length - 1;
    if (remaining < group.minAssignments) {
      return {
        result: RoleAssignmentResult._rejected(
          role,
          context,
          true,
          `role group '${group.id}' requires at least ${group.minAssignments} role(s)` +
            `${context === null ? '' : ` in context ${context}`}; unassigning would leave ${remaining}`,
        ),
        updated: null,
      };
    }
  }

  const updated = [...current];
  updated.splice(index, 1);
  return { result: RoleAssignmentResult._unassigned(role, context), updated: Object.freeze(updated) };
}

function rolesIn(assignments: readonly RoleAssignment[], context: string | null): readonly Role[] {
  return Object.freeze(
    assignments.filter((assignment) => assignment.context === context).map((assignment) => assignment.role),
  );
}

/**
 * The roles in `assignments` held in `context` that belong to `group`,
 * failing if any of them carries a conflicting definition of the same
 * group id — otherwise the limits applied would depend on which instance
 * the caller happened to pass in.
 */
function heldIn(assignments: readonly RoleAssignment[], group: RoleGroup, context: string | null): readonly Role[] {
  const held: Role[] = [];
  for (const assignment of assignments) {
    const role = assignment.role;
    const other = role.group;
    if (other === null || !other.equals(group)) {
      continue;
    }
    requireSameDefinition(group, other, role);
    if (assignment.context === context) {
      held.push(role);
    }
  }
  return Object.freeze(held);
}

function requireSameDefinition(group: RoleGroup, other: RoleGroup, role: Role): void {
  if (!group._sameDefinition(other)) {
    throw new IllegalStateError(
      `role group '${group.id}' has conflicting definitions: role '${role.id}' was built with different ` +
        'limits or a different policy; build the group once and share it between its roles',
    );
  }
}

/**
 * Checks a policy's replacement against the group before anything is
 * written, so a buggy custom policy fails loudly instead of leaving the
 * target in a state the group forbids.
 */
function checkReplacement(group: RoleGroup, held: readonly Role[], removed: readonly Role[]): void {
  if (new Set(removed.map((role) => role.id)).size !== removed.length) {
    throw new IllegalStateError(
      `assignment policy of group '${group.id}' replaced a role twice: [${removed.join(', ')}]`,
    );
  }
  for (const role of removed) {
    if (!held.some((heldRole) => heldRole.equals(role))) {
      throw new IllegalStateError(
        `assignment policy of group '${group.id}' replaced role '${role.id}', which the target does not hold in that group`,
      );
    }
  }
  const after = held.length - removed.length + 1;
  if (after > group.maxAssignments) {
    throw new IllegalStateError(
      `assignment policy of group '${group.id}' leaves ${after} role(s), over the maximum of ${group.maxAssignments}`,
    );
  }
  if (after < group.minAssignments) {
    throw new IllegalStateError(
      `assignment policy of group '${group.id}' leaves ${after} role(s), under the minimum of ${group.minAssignments}`,
    );
  }
}

/** The read-only subject over a target's assignments: live for the sync API, loaded once for the async one. */
class AssignedRolesSubject implements PermissionSubject {
  readonly #assignments: () => readonly RoleAssignment[];
  readonly #policy: PermissionResolutionPolicy;
  readonly #contextPolicy: ContextPolicy;
  readonly #description: string;

  constructor(
    assignments: () => readonly RoleAssignment[],
    policy: PermissionResolutionPolicy,
    contextPolicy: ContextPolicy,
    description: string,
  ) {
    this.#assignments = assignments;
    this.#policy = policy;
    this.#contextPolicy = contextPolicy;
    this.#description = description;
  }

  hasPermission(node: string, context?: string | null): boolean {
    const requested = context ?? null;
    return resolve(this.#policy, this.#applicable(node, requested), node, requested);
  }

  /**
   * Explains {@link hasPermission}: one contribution per applicable
   * assignment, with the role's own explanation. For a built-in policy the
   * decision, the deciding layer and the decisive roles are reported; a
   * custom policy is reported with `PARTIAL` provenance, since how it
   * combined the roles is not known.
   */
  explain(node: string, context?: string | null): PermissionExplanation {
    const requested = context ?? null;
    return explainResolution(this.#applicable(node, requested), node, requested, this.#policy, this.#contextPolicy);
  }

  /** Validates the check and returns the target's assignments that apply to it. */
  #applicable(node: string, context: string | null): readonly RoleAssignment[] {
    validateNode(node);
    PermissionGrant.requireValidContext(context);
    return Object.freeze(
      this.#assignments().filter((assignment) => this.#contextPolicy.applies(assignment.context, context)),
    );
  }

  grant(): never {
    throw new UnsupportedOperationError('a role-assignment subject is read-only; assign a role instead');
  }

  revoke(): never {
    throw new UnsupportedOperationError('a role-assignment subject is read-only; unassign a role instead');
  }

  toString(): string {
    return this.#description;
  }
}

/** A frozen copy of what a store returned, checked to be a list of assignments. */
function snapshot(assignments: unknown): readonly RoleAssignment[] {
  if (!Array.isArray(assignments)) {
    throw new IllegalStateError(
      'the store did not return an array of assignments; a store that returns a Promise needs AsyncRoleAssignments',
    );
  }
  for (const assignment of assignments) {
    if (!(assignment instanceof RoleAssignment)) {
      throw new IllegalStateError('the store returned something that is not a RoleAssignment');
    }
  }
  return Object.freeze([...assignments]);
}

function requireBoolean(replaced: unknown): boolean {
  if (replaced !== true && replaced !== false) {
    throw new IllegalStateError(
      'the store did not report whether it replaced the assignments; a store that returns a Promise needs AsyncRoleAssignments',
    );
  }
  return replaced;
}

function requireTarget(target: unknown): void {
  if (target === null || target === undefined) {
    throw new IllegalArgumentError('target must not be null');
  }
}

function requireStore<S extends { assignments: unknown; replace: unknown }>(store: S): S {
  if (store === null || typeof store !== 'object' || typeof store.assignments !== 'function' || typeof store.replace !== 'function') {
    throw new IllegalArgumentError('store must be a RoleAssignmentStore');
  }
  return store;
}

function requireContextPolicy(contextPolicy: ContextPolicy): ContextPolicy {
  if (!(contextPolicy instanceof ContextPolicy)) {
    throw new IllegalArgumentError('contextPolicy must be a ContextPolicy');
  }
  return contextPolicy;
}

function requirePolicy(policy: PermissionResolutionPolicy): PermissionResolutionPolicy {
  if (policy === null || typeof policy?.hasPermission !== 'function') {
    throw new IllegalArgumentError('policy must be a PermissionResolutionPolicy');
  }
  return policy;
}
