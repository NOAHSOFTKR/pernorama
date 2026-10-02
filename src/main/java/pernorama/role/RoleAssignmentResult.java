package pernorama.role;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The outcome of one {@link RoleAssignments#assign(Object, Role, String)}
 * or {@link RoleAssignments#unassign(Object, Role, String)} call: what
 * happened, in which context, and which roles it added or removed.
 * Enough to emit an audit event from, e.g. for a replacement:
 *
 * <pre>{@code
 * RoleAssignmentResult result = assignments.assign(user, max5);
 * if (result.status() == RoleAssignmentStatus.REPLACED) {
 *     audit("ROLE_REPLACED", user, result.previousRole(), result.currentRole());
 * }
 * }</pre>
 *
 * Immutable.
 */
public final class RoleAssignmentResult {

    private final RoleAssignmentStatus status;
    private final Role role;
    private final String context;
    private final List<Role> removedRoles;
    private final boolean held;
    private final String rejectionReason;

    private RoleAssignmentResult(RoleAssignmentStatus status, Role role, String context, List<Role> removedRoles,
                                 boolean held, String rejectionReason) {
        this.status = status;
        this.role = role;
        this.context = context;
        this.removedRoles = removedRoles;
        this.held = held;
        this.rejectionReason = rejectionReason;
    }

    static RoleAssignmentResult assigned(Role role, String context) {
        return new RoleAssignmentResult(RoleAssignmentStatus.ASSIGNED, role, context, List.of(), true, null);
    }

    static RoleAssignmentResult replaced(Role role, String context, List<Role> removedRoles) {
        return new RoleAssignmentResult(RoleAssignmentStatus.REPLACED, role, context, List.copyOf(removedRoles),
                true, null);
    }

    static RoleAssignmentResult unassigned(Role role, String context) {
        return new RoleAssignmentResult(RoleAssignmentStatus.UNASSIGNED, role, context, List.of(role), false, null);
    }

    static RoleAssignmentResult noChange(Role role, String context, boolean held) {
        return new RoleAssignmentResult(RoleAssignmentStatus.NO_CHANGE, role, context, List.of(), held, null);
    }

    static RoleAssignmentResult rejected(Role role, String context, boolean held, String reason) {
        return new RoleAssignmentResult(RoleAssignmentStatus.REJECTED, role, context, List.of(), held,
                Objects.requireNonNull(reason, "reason"));
    }

    /** What happened. */
    public RoleAssignmentStatus status() {
        return status;
    }

    /** The role that was asked to be assigned or unassigned. */
    public Role role() {
        return role;
    }

    /**
     * The context the role was asked to be assigned or unassigned in, if
     * any. Every role in {@link #removedRoles()} was removed from this
     * same context.
     */
    public Optional<String> context() {
        return Optional.ofNullable(context);
    }

    /** The group of {@link #role()}, if it has one. */
    public Optional<RoleGroup> group() {
        return role.group();
    }

    /**
     * Every role this call removed: the replaced roles for
     * {@link RoleAssignmentStatus#REPLACED}, the role itself for
     * {@link RoleAssignmentStatus#UNASSIGNED}, and nothing otherwise.
     */
    public List<Role> removedRoles() {
        return removedRoles;
    }

    /**
     * The first role in {@link #removedRoles()} — for a replacement in an
     * exclusive group, the one role that was swapped out.
     */
    public Optional<Role> previousRole() {
        return removedRoles.isEmpty() ? Optional.empty() : Optional.of(removedRoles.get(0));
    }

    /**
     * {@link #role()} if the target holds it in {@link #context()} after
     * this call, otherwise empty.
     */
    public Optional<Role> currentRole() {
        return held ? Optional.of(role) : Optional.empty();
    }

    /** Why the call was rejected, for {@link RoleAssignmentStatus#REJECTED}. */
    public Optional<String> rejectionReason() {
        return Optional.ofNullable(rejectionReason);
    }

    @Override
    public String toString() {
        return "RoleAssignmentResult[status=" + status + ", role=" + role
                + (context == null ? "" : ", context=" + context) + ", removed=" + removedRoles
                + (rejectionReason == null ? "" : ", reason=" + rejectionReason) + "]";
    }
}
