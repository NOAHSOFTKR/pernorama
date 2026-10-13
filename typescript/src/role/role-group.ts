import { IllegalArgumentError } from '../error/errors.js';
import { RoleAssignmentPolicy } from './role-assignment-policy.js';
import { requireValidId } from './role-ids.js';

/** `maxAssignments` of a group with no maximum: Java's `Integer.MAX_VALUE`. */
const UNBOUNDED = 2_147_483_647;

/**
 * Constraints shared by a set of related `Role`s: how many of them one
 * target may hold at once, and what happens when an assignment would go
 * over that limit.
 *
 * ```ts
 * const plan = RoleGroup.builder('plan')
 *   .maxAssignments(1)
 *   .assignmentPolicy(RoleAssignmentPolicy.REPLACE_EXISTING)
 *   .build();
 * ```
 *
 * ## Cardinality
 * {@link maxAssignments} is enforced when a role is assigned: an
 * assignment that would take a target over it is handed to
 * {@link assignmentPolicy}, which either rejects it or names the roles it
 * replaces. {@link minAssignments} is enforced when a role is unassigned:
 * removing a role that would take a target under it is rejected. A target
 * that starts out under the minimum — every target does, before its first
 * assignment — is not an error; it just cannot lose roles it needs to stay
 * there.
 *
 * Both limits are counted per context: only the roles a target holds in
 * the context being assigned or unassigned in count, so a target can hold
 * one role of an exclusive group in each of several contexts. Roles held
 * without a context are counted together, as one more context.
 *
 * ## Identity
 * A group is identified by its {@link id}: two groups with the same id are
 * {@link equals equal}, and roles that point at either count against the
 * same limit. One id must therefore have one definition. Build each group
 * once and share it between its roles; if two instances with the same id
 * disagree on their limits or policy (compared by reference),
 * `RoleAssignments` throws `IllegalStateError` and changes nothing as soon
 * as it sees them in the same group.
 *
 * Immutable.
 */
export class RoleGroup {
  /** {@link maxAssignments} of a group with no maximum. */
  static readonly UNBOUNDED: number = UNBOUNDED;

  /** The id identifying this group. */
  readonly id: string;
  /** The fewest roles of this group a target may be left holding by an unassignment. */
  readonly minAssignments: number;
  /** The most roles of this group a target may hold at once; {@link RoleGroup.UNBOUNDED} when unbounded. */
  readonly maxAssignments: number;
  /** What happens when an assignment would go over {@link maxAssignments}. */
  readonly assignmentPolicy: RoleAssignmentPolicy;

  private constructor(id: string, min: number, max: number, policy: RoleAssignmentPolicy) {
    this.id = id;
    this.minAssignments = min;
    this.maxAssignments = max;
    this.assignmentPolicy = policy;
    Object.freeze(this);
  }

  /**
   * Starts building a group with the given id. Unless changed, a group has
   * no minimum, no maximum, and the `RoleAssignmentPolicy.REJECT` policy.
   *
   * @throws IllegalArgumentError if `id` is blank, or has leading or
   *         trailing whitespace
   */
  static builder(id: string): RoleGroupBuilder {
    requireValidId(id, 'group id');
    return new RoleGroupBuilder((min, max, policy) => new RoleGroup(id, min, max, policy));
  }

  /**
   * Whether `other` is the same group with the same limits and the same
   * policy instance; {@link equals} only compares ids.
   *
   * @internal
   */
  _sameDefinition(other: RoleGroup): boolean {
    return (
      this === other ||
      (this.id === other.id &&
        this.minAssignments === other.minAssignments &&
        this.maxAssignments === other.maxAssignments &&
        this.assignmentPolicy === other.assignmentPolicy)
    );
  }

  /** Two groups are equal if they have the same id. */
  equals(other: unknown): boolean {
    return other instanceof RoleGroup && other.id === this.id;
  }

  toString(): string {
    return this.id;
  }
}

/** Builder for {@link RoleGroup}; get one from `RoleGroup.builder`. */
export class RoleGroupBuilder {
  readonly #create: (min: number, max: number, policy: RoleAssignmentPolicy) => RoleGroup;
  #minAssignments = 0;
  #maxAssignments = UNBOUNDED;
  #assignmentPolicy: RoleAssignmentPolicy = RoleAssignmentPolicy.REJECT;

  /** @internal */
  constructor(create: (min: number, max: number, policy: RoleAssignmentPolicy) => RoleGroup) {
    this.#create = create;
  }

  /** Sets the minimum; must be an integer `>= 0`. Defaults to `0`. */
  minAssignments(minAssignments: number): this {
    this.#minAssignments = minAssignments;
    return this;
  }

  /** Sets the maximum; must be an integer `>= 1`. Defaults to unbounded. */
  maxAssignments(maxAssignments: number): this {
    this.#maxAssignments = maxAssignments;
    return this;
  }

  /** Sets the overflow policy. Defaults to `RoleAssignmentPolicy.REJECT`. */
  assignmentPolicy(assignmentPolicy: RoleAssignmentPolicy): this {
    if (assignmentPolicy === null || typeof assignmentPolicy?.decide !== 'function') {
      throw new IllegalArgumentError('assignmentPolicy must be a RoleAssignmentPolicy');
    }
    this.#assignmentPolicy = assignmentPolicy;
    return this;
  }

  /**
   * Builds the group.
   *
   * @throws IllegalArgumentError if a limit is not a 32-bit integer, the
   *         minimum is negative, the maximum is less than `1`, the minimum
   *         is greater than the maximum, or the policy is
   *         `RoleAssignmentPolicy.REPLACE_EXISTING` with a minimum above
   *         `1`, which it could never satisfy
   */
  build(): RoleGroup {
    const min = this.#minAssignments;
    const max = this.#maxAssignments;
    for (const [name, value] of [['minAssignments', min], ['maxAssignments', max]] as const) {
      if (!Number.isInteger(value) || Math.abs(value) > UNBOUNDED) {
        // Java's limits are ints; anything else could not round-trip
        throw new IllegalArgumentError(`${name} must be an integer: ${String(value)}`);
      }
    }
    if (min < 0) {
      throw new IllegalArgumentError(`minAssignments must be >= 0: ${min}`);
    }
    if (max < 1) {
      throw new IllegalArgumentError(`maxAssignments must be >= 1: ${max}`);
    }
    if (min > max) {
      throw new IllegalArgumentError(`minAssignments (${min}) must not exceed maxAssignments (${max})`);
    }
    if (this.#assignmentPolicy === RoleAssignmentPolicy.REPLACE_EXISTING && min > 1) {
      throw new IllegalArgumentError(
        `REPLACE_EXISTING leaves one role, below minAssignments (${min}); use REPLACE_OLDEST or REPLACE_NEWEST`,
      );
    }
    return this.#create(min, max, this.#assignmentPolicy);
  }
}
