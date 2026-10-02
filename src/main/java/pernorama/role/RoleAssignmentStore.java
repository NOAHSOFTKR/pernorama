package pernorama.role;

import java.util.List;

/**
 * Where {@link RoleAssignments} keeps which roles each target holds, and
 * in which contexts, as a list of {@link RoleAssignment}s. The
 * core ships {@link MemoryRoleAssignmentStore}; a database-backed
 * application implements this against its own tables.
 * <p>
 * The contract is deliberately small — a read and a compare-and-set — so
 * that the policy logic lives in one place ({@link RoleAssignments}) and
 * an adapter only has to provide atomicity:
 *
 * <ul>
 *   <li>{@link #assignments(Object)} returns a consistent snapshot of
 *       the target's assignments, oldest first, across every context.
 *       The order is what {@link RoleAssignmentPolicy#REPLACE_OLDEST} and
 *       {@link RoleAssignmentPolicy#REPLACE_NEWEST} rely on, so a store
 *       has to preserve it.</li>
 *   <li>{@link #replace(Object, List, List)} changes the target's assignments
 *       from {@code expected} to {@code updated} <b>as one atomic
 *       step</b>, and only if they are still {@code expected}. A
 *       replacement — one role out, another in — is a single call, so
 *       no reader may ever observe the target with the old role removed
 *       but the new one not yet added. A relational store would typically
 *       run the comparison and the write in one transaction, or guard
 *       them with a version column.</li>
 * </ul>
 *
 * Assignments are compared with {@link RoleAssignment#equals(Object)},
 * i.e. by role id and context. A relational store would typically keep
 * one row per assignment — target, role id, context (nullable) and an
 * ordering column.
 *
 * @param <K> how a target is identified
 */
public interface RoleAssignmentStore<K> {

    /**
     * The assignments {@code target} holds in every context, oldest
     * first; empty if none. Never {@code null}.
     */
    List<RoleAssignment> assignments(K target);

    /**
     * Atomically sets {@code target}'s assignments to {@code updated} if they
     * currently equal {@code expected}, and reports whether it did. When
     * this returns {@code false} nothing was changed. It must return
     * {@code true} whenever the assignments do equal {@code expected}:
     * {@link RoleAssignments} retries until a write succeeds, so a store
     * that fails spuriously — on a transient database conflict, say —
     * should retry that failure itself or throw, not return
     * {@code false}.
     */
    boolean replace(K target, List<RoleAssignment> expected, List<RoleAssignment> updated);
}
