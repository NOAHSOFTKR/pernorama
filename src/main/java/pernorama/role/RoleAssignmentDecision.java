package pernorama.role;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * What a {@link RoleAssignmentPolicy} decided about an assignment that
 * would overflow its group: {@link #reject(String) reject} it, or
 * {@link #replace(Collection) replace} some held roles to make room.
 * <p>
 * Immutable.
 */
public final class RoleAssignmentDecision {

    private final String rejectionReason;
    private final List<Role> replacedRoles;

    private RoleAssignmentDecision(String rejectionReason, List<Role> replacedRoles) {
        this.rejectionReason = rejectionReason;
        this.replacedRoles = replacedRoles;
    }

    /** Rejects the assignment for the given human-readable reason. */
    public static RoleAssignmentDecision reject(String reason) {
        return new RoleAssignmentDecision(Objects.requireNonNull(reason, "reason"), List.of());
    }

    /**
     * Accepts the assignment by removing {@code roles}, which must all be
     * held by the target in the group, in the context being assigned in,
     * in the same atomic change that adds the new role.
     */
    public static RoleAssignmentDecision replace(Collection<Role> roles) {
        return new RoleAssignmentDecision(null, List.copyOf(Objects.requireNonNull(roles, "roles")));
    }

    /** Whether the assignment was rejected. */
    public boolean isRejected() {
        return rejectionReason != null;
    }

    /** Why the assignment was rejected, if it was. */
    public Optional<String> rejectionReason() {
        return Optional.ofNullable(rejectionReason);
    }

    /** The roles to remove; empty for a rejection. */
    public List<Role> replacedRoles() {
        return replacedRoles;
    }
}
