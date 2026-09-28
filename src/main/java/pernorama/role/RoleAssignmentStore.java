package pernorama.role;

import java.util.List;

/**
 * Where {@link RoleAssignments} keeps which roles each target holds. The
 * core ships {@link MemoryRoleAssignmentStore}; a database-backed
 * application implements this against its own tables.
 * <p>
 * The contract is deliberately small — a read and a compare-and-set — so
 * that the policy logic lives in one place ({@link RoleAssignments}) and
 * an adapter only has to provide atomicity:
 *
 * <ul>
 *   <li>{@link #roles(Object)} returns a consistent snapshot of the
 *       target's roles, oldest assignment first. The order is what
 *       {@link RoleAssignmentPolicy#REPLACE_OLDEST} and
 *       {@link RoleAssignmentPolicy#REPLACE_NEWEST} rely on, so a store
 *       has to preserve it.</li>
 *   <li>{@link #replace(Object, List, List)} changes the target's roles
 *       from {@code expected} to {@code updated} <b>as one atomic
 *       step</b>, and only if they are still {@code expected}. A
 *       replacement — one role out, another in — is a single call, so
 *       no reader may ever observe the target with the old role removed
 *       but the new one not yet added. A relational store would typically
 *       run the comparison and the write in one transaction, or guard
 *       them with a version column.</li>
 * </ul>
 *
 * Roles are compared with {@link Role#equals(Object)}, i.e. by id.
 *
 * @param <K> how a target is identified
 */
public interface RoleAssignmentStore<K> {

    /**
     * The roles {@code target} holds, oldest assignment first; empty if
     * none. Never {@code null}.
     */
    List<Role> roles(K target);

    /**
     * Atomically sets {@code target}'s roles to {@code updated} if they
     * currently equal {@code expected}, and reports whether it did. When
     * this returns {@code false} nothing was changed.
     */
    boolean replace(K target, List<Role> expected, List<Role> updated);
}
