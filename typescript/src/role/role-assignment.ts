import { IllegalArgumentError } from '../error/errors.js';
import { PermissionGrant } from '../permission/permission-grant.js';
import { Role } from './role.js';
import type { RoleGroup } from './role-group.js';

/**
 * One role held by a target, in a context or without one:
 *
 * ```ts
 * new RoleAssignment(teacher, 'academy:123'); // a teacher in academy:123
 * new RoleAssignment(staff);                  // staff, with no context
 * ```
 *
 * The context is the same kind of opaque, application-defined string a
 * `PermissionGrant` carries, and `null` means no context. Where a role
 * assigned in a context applies is decided by the `ContextPolicy` of the
 * `RoleAssignments` holding it, exactly as for a grant in that context.
 *
 * Two assignments are {@link equals equal} if they assign the same role —
 * by id — in the same context, so one target can hold the same role in
 * several contexts.
 */
export class RoleAssignment {
  /** The role held. */
  readonly role: Role;
  /** The context it is held in, or `null` for none. */
  readonly context: string | null;

  /**
   * @throws IllegalArgumentError if `role` is not a `Role`, or `context`
   *         is empty
   */
  constructor(role: Role, context?: string | null) {
    if (!(role instanceof Role)) {
      throw new IllegalArgumentError('role must be a Role');
    }
    this.role = role;
    this.context = PermissionGrant.requireValidContext(context);
    Object.freeze(this);
  }

  /** Whether this assignment is scoped to a context. */
  get hasContext(): boolean {
    return this.context !== null;
  }

  /** Two assignments are equal if they assign the same role id in the same context. */
  equals(other: unknown): boolean {
    return other instanceof RoleAssignment && other.role.equals(this.role) && other.context === this.context;
  }

  toString(): string {
    return this.context === null ? this.role.id : `${this.role.id} @ ${this.context}`;
  }
}

/** The outcome of a `RoleAssignments` operation. */
export const RoleAssignmentStatus = {
  /** The role was added and nothing was removed. */
  ASSIGNED: 'ASSIGNED',
  /** The role was added and one or more held roles were removed in the same change. */
  REPLACED: 'REPLACED',
  /** The role was removed. */
  UNASSIGNED: 'UNASSIGNED',
  /**
   * Nothing changed because the target was already in the requested state:
   * it already held the role being assigned, or did not hold the role
   * being unassigned.
   */
  NO_CHANGE: 'NO_CHANGE',
  /** Nothing changed because the operation would have broken a group constraint. */
  REJECTED: 'REJECTED',
} as const;

export type RoleAssignmentStatus = (typeof RoleAssignmentStatus)[keyof typeof RoleAssignmentStatus];

/**
 * The outcome of one `assign` or `unassign` call: what happened, in which
 * context, and which roles it added or removed. Enough to emit an audit
 * event from, e.g. for a replacement:
 *
 * ```ts
 * const result = assignments.assign(user, max5);
 * if (result.status === RoleAssignmentStatus.REPLACED) {
 *   audit('ROLE_REPLACED', user, result.previousRole, result.currentRole);
 * }
 * ```
 *
 * Immutable.
 */
export class RoleAssignmentResult {
  /** What happened. */
  readonly status: RoleAssignmentStatus;
  /** The role that was asked to be assigned or unassigned. */
  readonly role: Role;
  /**
   * The context the role was asked to be assigned or unassigned in, or
   * `null` for none. Every role in {@link removedRoles} was removed from
   * this same context.
   */
  readonly context: string | null;
  /**
   * Every role this call removed: the replaced roles for `REPLACED`, the
   * role itself for `UNASSIGNED`, and nothing otherwise.
   */
  readonly removedRoles: readonly Role[];
  /** Why the call was rejected, for `REJECTED`; otherwise `null`. */
  readonly rejectionReason: string | null;
  readonly #held: boolean;

  private constructor(
    status: RoleAssignmentStatus,
    role: Role,
    context: string | null,
    removedRoles: readonly Role[],
    held: boolean,
    rejectionReason: string | null,
  ) {
    this.status = status;
    this.role = role;
    this.context = context;
    this.removedRoles = Object.freeze([...removedRoles]);
    this.#held = held;
    this.rejectionReason = rejectionReason;
    Object.freeze(this);
  }

  /** @internal */
  static _assigned(role: Role, context: string | null): RoleAssignmentResult {
    return new RoleAssignmentResult(RoleAssignmentStatus.ASSIGNED, role, context, [], true, null);
  }

  /** @internal */
  static _replaced(role: Role, context: string | null, removedRoles: readonly Role[]): RoleAssignmentResult {
    return new RoleAssignmentResult(RoleAssignmentStatus.REPLACED, role, context, removedRoles, true, null);
  }

  /** @internal */
  static _unassigned(role: Role, context: string | null): RoleAssignmentResult {
    return new RoleAssignmentResult(RoleAssignmentStatus.UNASSIGNED, role, context, [role], false, null);
  }

  /** @internal */
  static _noChange(role: Role, context: string | null, held: boolean): RoleAssignmentResult {
    return new RoleAssignmentResult(RoleAssignmentStatus.NO_CHANGE, role, context, [], held, null);
  }

  /** @internal */
  static _rejected(role: Role, context: string | null, held: boolean, reason: string): RoleAssignmentResult {
    return new RoleAssignmentResult(RoleAssignmentStatus.REJECTED, role, context, [], held, reason);
  }

  /** The group of {@link role}, or `null` if it has none. */
  get group(): RoleGroup | null {
    return this.role.group;
  }

  /**
   * The first role in {@link removedRoles} — for a replacement in an
   * exclusive group, the one role that was swapped out — or `null`.
   */
  get previousRole(): Role | null {
    return this.removedRoles[0] ?? null;
  }

  /** {@link role} if the target holds it in {@link context} after this call, otherwise `null`. */
  get currentRole(): Role | null {
    return this.#held ? this.role : null;
  }

  toString(): string {
    return (
      `RoleAssignmentResult[status=${this.status}, role=${this.role}` +
      `${this.context === null ? '' : `, context=${this.context}`}, removed=[${this.removedRoles.join(', ')}]` +
      `${this.rejectionReason === null ? '' : `, reason=${this.rejectionReason}`}]`
    );
  }
}
