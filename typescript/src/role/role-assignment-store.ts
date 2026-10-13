import { IllegalArgumentError } from '../error/errors.js';
import type { RoleAssignment } from './role-assignment.js';

/**
 * Where `RoleAssignments` keeps which roles each target holds, and in
 * which contexts, as a list of {@link RoleAssignment}s. The core ships
 * {@link MemoryRoleAssignmentStore}; see {@link AsyncRoleAssignmentStore}
 * for a store that has to do I/O.
 *
 * The contract is deliberately small — a read and a compare-and-set — so
 * that the policy logic lives in one place (`RoleAssignments`) and an
 * adapter only has to provide atomicity:
 *
 * - {@link assignments} returns a consistent snapshot of the target's
 *   assignments, oldest first, across every context. The order is what
 *   `RoleAssignmentPolicy.REPLACE_OLDEST` and `REPLACE_NEWEST` rely on, so
 *   a store has to preserve it.
 * - {@link replace} changes the target's assignments from `expected` to
 *   `updated` **as one atomic step**, and only if they are still
 *   `expected`. A replacement — one role out, another in — is a single
 *   call, so no reader may ever observe the target with the old role
 *   removed but the new one not yet added.
 *
 * Assignments are compared with `RoleAssignment.equals`, i.e. by role id
 * and context.
 *
 * @typeParam K how a target is identified
 */
export interface RoleAssignmentStore<K> {
  /** The assignments `target` holds in every context, oldest first; empty if none. */
  assignments(target: K): readonly RoleAssignment[];

  /**
   * Atomically sets `target`'s assignments to `updated` if they currently
   * equal `expected`, and reports whether it did. When this returns
   * `false` nothing was changed. It must return `true` whenever the
   * assignments do equal `expected`: `RoleAssignments` retries until a
   * write succeeds, so a store that fails spuriously should retry that
   * failure itself or throw, not return `false`.
   */
  replace(target: K, expected: readonly RoleAssignment[], updated: readonly RoleAssignment[]): boolean;
}

/**
 * A {@link RoleAssignmentStore} that may answer asynchronously — the shape
 * a database-backed store has in Node.js. Same contract, used through
 * `AsyncRoleAssignments`. Has no Java counterpart, where a store blocks.
 *
 * The atomicity requirement is what matters here: {@link replace} has to
 * compare and write **in the database**, in one statement or one
 * transaction — a version column (`UPDATE ... WHERE version = ?`), a
 * serializable transaction that re-reads the rows, or a row lock. Reading
 * in one round trip and writing in the next without such a guard is not a
 * compare-and-set, and lets two concurrent assignments both go over a
 * group's maximum. A relational store would typically keep one row per
 * assignment — target, role id, context (nullable) and an ordering
 * column — plus a per-target version.
 *
 * Every synchronous store is also an `AsyncRoleAssignmentStore`.
 *
 * @typeParam K how a target is identified
 */
export interface AsyncRoleAssignmentStore<K> {
  /** The assignments `target` holds in every context, oldest first; empty if none. */
  assignments(target: K): readonly RoleAssignment[] | PromiseLike<readonly RoleAssignment[]>;

  /**
   * Atomically sets `target`'s assignments to `updated` if they currently
   * equal `expected`, and reports whether it did; see
   * {@link RoleAssignmentStore.replace}.
   */
  replace(
    target: K,
    expected: readonly RoleAssignment[],
    updated: readonly RoleAssignment[],
  ): boolean | PromiseLike<boolean>;
}

const EMPTY: readonly RoleAssignment[] = Object.freeze([]);

/**
 * An in-memory {@link RoleAssignmentStore}, the default for
 * `RoleAssignments`.
 *
 * Each target's assignments are held as an immutable list, and
 * {@link replace} compares and swaps it without yielding, so a reader
 * always sees either the whole list before a change or the whole list
 * after it.
 *
 * @typeParam K how a target is identified. Targets are looked up as `Map`
 *            keys, so use a primitive such as a user id; two distinct
 *            objects are two distinct targets even if they look alike.
 */
export class MemoryRoleAssignmentStore<K> implements RoleAssignmentStore<K> {
  readonly #assignments = new Map<K, readonly RoleAssignment[]>();

  assignments(target: K): readonly RoleAssignment[] {
    requireTarget(target);
    return this.#assignments.get(target) ?? EMPTY;
  }

  replace(target: K, expected: readonly RoleAssignment[], updated: readonly RoleAssignment[]): boolean {
    requireTarget(target);
    if (!Array.isArray(expected) || !Array.isArray(updated)) {
      throw new IllegalArgumentError('expected and updated must be arrays');
    }
    const actual = this.#assignments.get(target) ?? EMPTY;
    if (!sameAssignments(actual, expected)) {
      return false;
    }
    if (updated.length === 0) {
      this.#assignments.delete(target);
    } else {
      this.#assignments.set(target, Object.freeze([...updated]));
    }
    return true;
  }
}

/** Whether two lists hold equal assignments in the same order. */
export function sameAssignments(a: readonly RoleAssignment[], b: readonly RoleAssignment[]): boolean {
  return a.length === b.length && a.every((assignment, i) => assignment.equals(b[i]));
}

function requireTarget(target: unknown): void {
  if (target === null || target === undefined) {
    throw new IllegalArgumentError('target must not be null');
  }
}
