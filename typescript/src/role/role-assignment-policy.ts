import { IllegalArgumentError } from '../error/errors.js';
import type { Role } from './role.js';
import type { RoleGroup } from './role-group.js';

/**
 * What a {@link RoleAssignmentPolicy} decided about an assignment that
 * would overflow its group: {@link RoleAssignmentDecision.reject reject}
 * it, or {@link RoleAssignmentDecision.replace replace} some held roles to
 * make room.
 *
 * Immutable.
 */
export class RoleAssignmentDecision {
  /** Why the assignment was rejected, or `null` if it was not. */
  readonly rejectionReason: string | null;
  /** The roles to remove; empty for a rejection. */
  readonly replacedRoles: readonly Role[];

  private constructor(rejectionReason: string | null, replacedRoles: readonly Role[]) {
    this.rejectionReason = rejectionReason;
    this.replacedRoles = Object.freeze([...replacedRoles]);
    Object.freeze(this);
  }

  /** Rejects the assignment for the given human-readable reason. */
  static reject(reason: string): RoleAssignmentDecision {
    if (typeof reason !== 'string') {
      throw new IllegalArgumentError('reason must be a string');
    }
    return new RoleAssignmentDecision(reason, []);
  }

  /**
   * Accepts the assignment by removing `roles`, which must all be held by
   * the target in the group, in the context being assigned in, in the same
   * atomic change that adds the new role.
   */
  static replace(roles: Iterable<Role>): RoleAssignmentDecision {
    if (roles === null || roles === undefined) {
      throw new IllegalArgumentError('roles must not be null');
    }
    return new RoleAssignmentDecision(null, [...roles]);
  }

  /** Whether the assignment was rejected. */
  get isRejected(): boolean {
    return this.rejectionReason !== null;
  }
}

/**
 * Decides what happens when assigning a role would take a target over its
 * `RoleGroup`'s maximum: reject the assignment, or replace some of the
 * roles the target already holds in that group.
 *
 * A policy is only consulted on overflow. Assigning a role the target
 * already holds is a no-op that never reaches it, and an assignment that
 * fits within the maximum simply happens.
 *
 * This is only about which roles may coexist. How the permissions of
 * several held roles combine is a separate question, answered by
 * `PermissionResolutionPolicy`.
 *
 * ## Custom policies
 * Implement {@link RoleAssignmentPolicy.decide} and pass the policy to
 * `RoleGroupBuilder.assignmentPolicy`. A policy only decides;
 * `RoleAssignments` checks the decision and applies it as one atomic
 * change. It throws `IllegalStateError`, and changes nothing, if a
 * decision replaces a role the target does not hold in the group, still
 * leaves the target over the maximum, or takes it under the minimum. A
 * policy may be called more than once for one assignment if a concurrent
 * change forces a retry, so it should have no side effects.
 */
export interface RoleAssignmentPolicy {
  /**
   * Decides an assignment that would go over the group's maximum.
   *
   * @param group     the group of `requested`, whose limits apply
   * @param held      the roles the target holds in `group` in the context
   *                  being assigned in, oldest assignment first. Roles
   *                  held in other contexts are not counted and cannot be
   *                  replaced.
   * @param requested the role being assigned, not in `held`
   */
  decide(group: RoleGroup, held: readonly Role[], requested: Role): RoleAssignmentDecision;
}

/** How many held roles have to go for one more to fit. */
function overflow(group: RoleGroup, held: readonly Role[]): number {
  return Math.min(held.length, held.length - group.maxAssignments + 1);
}

/** The built-in policies. Compare with `===`. */
export const RoleAssignmentPolicy: {
  /** Rejects the assignment; the target keeps the roles it has. */
  readonly REJECT: RoleAssignmentPolicy;
  /**
   * Replaces every role the target holds in the group, so the new role is
   * the only one left. Meant for exclusive groups (`maxAssignments(1)`),
   * where it swaps one role for another; in a larger group use
   * `REPLACE_OLDEST` or `REPLACE_NEWEST` to make room for just one.
   * Because it leaves a single role, a group with a minimum above `1`
   * cannot use it; `RoleGroupBuilder.build` rejects that combination.
   */
  readonly REPLACE_EXISTING: RoleAssignmentPolicy;
  /** Replaces the roles the target has held longest, as few as needed to make room. */
  readonly REPLACE_OLDEST: RoleAssignmentPolicy;
  /** Replaces the roles the target was given most recently, as few as needed to make room. */
  readonly REPLACE_NEWEST: RoleAssignmentPolicy;
} = Object.freeze({
  REJECT: Object.freeze({
    decide: (group: RoleGroup, held: readonly Role[]) =>
      RoleAssignmentDecision.reject(
        `role group '${group.id}' allows at most ${group.maxAssignments} role(s) and the target already holds ${held.length}`,
      ),
  }),
  REPLACE_EXISTING: Object.freeze({
    decide: (_group: RoleGroup, held: readonly Role[]) => RoleAssignmentDecision.replace(held),
  }),
  REPLACE_OLDEST: Object.freeze({
    decide: (group: RoleGroup, held: readonly Role[]) =>
      RoleAssignmentDecision.replace(held.slice(0, overflow(group, held))),
  }),
  REPLACE_NEWEST: Object.freeze({
    decide: (group: RoleGroup, held: readonly Role[]) =>
      RoleAssignmentDecision.replace(held.slice(held.length - overflow(group, held))),
  }),
});
