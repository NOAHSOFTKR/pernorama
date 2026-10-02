package pernorama.role;

import pernorama.permission.PermissionGrant;

import java.util.Objects;

/**
 * One role held by a target, in a context or without one:
 *
 * <pre>{@code
 * new RoleAssignment(teacher, "academy:123"); // a teacher in academy:123
 * new RoleAssignment(staff, null);            // staff, with no context
 * }</pre>
 *
 * The context is the same kind of opaque, application-defined string a
 * {@link PermissionGrant} carries, and {@code null} means no context.
 * Where a role assigned in a context applies is decided by the
 * {@link pernorama.permission.ContextPolicy} of the
 * {@link RoleAssignments} holding it, exactly as for a grant in that
 * context.
 * <p>
 * Two assignments are equal if they assign the same role — by
 * {@linkplain Role#equals(Object) id} — in the same context, so one
 * target can hold the same role in several contexts.
 *
 * @param role    the role held
 * @param context the context it is held in, or {@code null} for none
 */
public record RoleAssignment(Role role, String context) {

    /**
     * Creates an assignment, validating both components.
     *
     * @throws NullPointerException if {@code role} is null
     * @throws IllegalArgumentException if {@code context} is empty
     */
    public RoleAssignment {
        Objects.requireNonNull(role, "role");
        PermissionGrant.requireValidContext(context);
    }

    /** Whether this assignment is scoped to a context. */
    public boolean hasContext() {
        return context != null;
    }

    @Override
    public String toString() {
        return context == null ? role.id() : role.id() + " @ " + context;
    }
}
