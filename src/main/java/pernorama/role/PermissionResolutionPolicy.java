package pernorama.role;

import pernorama.subject.CompositePermissionSubject;

import java.util.List;

/**
 * Decides whether a target is permitted a node, given every role it
 * holds. Each role still answers for itself — through
 * {@link Role#permissions()} and {@link Role#denies(String)}, which use
 * the core's matching rules — and a policy only combines those answers.
 * <p>
 * Which roles a target may hold together is a separate question,
 * answered by {@link RoleAssignmentPolicy}.
 * <p>
 * Implement this interface for a combination the built-in policies do
 * not cover, e.g. one that ranks roles by their group. The node passed
 * in has already been validated.
 */
@FunctionalInterface
public interface PermissionResolutionPolicy {

    /**
     * Permitted if <b>any</b> role permits the node. A deny rule only
     * limits the role holding it. This is exactly how
     * {@link CompositePermissionSubject} combines its sources, and it is
     * the default for {@link RoleAssignments#subject(Object)}.
     */
    PermissionResolutionPolicy ALLOW_OVERRIDES = (roles, node) -> {
        for (Role role : roles) {
            if (role.permissions().hasPermission(node)) {
                return true;
            }
        }
        return false;
    };

    /**
     * Permitted if some role permits the node and <b>no</b> role
     * {@linkplain Role#denies(String) explicitly denies} it: a deny rule
     * in one role vetoes a grant in another. A role that simply does not
     * mention the node does not veto anything, and only a role built from
     * rules can deny.
     */
    PermissionResolutionPolicy DENY_OVERRIDES = (roles, node) -> {
        boolean permitted = false;
        for (Role role : roles) {
            if (role.permissions().hasPermission(node)) {
                permitted = true;
            } else if (role.denies(node)) {
                return false;
            }
        }
        return permitted;
    };

    /**
     * Returns whether {@code roles}, taken together, permit {@code node}.
     *
     * @param roles the target's roles, oldest assignment first; unmodifiable
     * @param node  a valid permission node
     */
    boolean hasPermission(List<Role> roles, String node);
}
