package pernorama.role;

import pernorama.subject.CompositePermissionSubject;

import java.util.List;

/**
 * Decides whether a target is permitted a node, given the role
 * assignments that apply to the check. Each role still answers for
 * itself — through {@link Role#permissions()} and {@link Role#denies(String)},
 * which use the core's matching rules — and a policy only combines those
 * answers.
 * <p>
 * Which assignments apply is settled before the policy is called:
 * {@link RoleAssignments} passes only those whose context its
 * {@link pernorama.permission.ContextPolicy} applies to the context being
 * checked. A role carries no context of its own, so each one is asked
 * without a context.
 * <p>
 * Which roles a target may hold together is a separate question,
 * answered by {@link RoleAssignmentPolicy}.
 * <p>
 * Implement this interface for a combination the built-in policies do
 * not cover — one that ranks roles by their group, say, or lets a role
 * assigned in the checked context outrank one assigned without a
 * context. The node and context passed in have already been validated.
 */
@FunctionalInterface
public interface PermissionResolutionPolicy {

    /**
     * Permitted if <b>any</b> applicable role permits the node. A deny
     * rule only limits the role holding it. This is exactly how
     * {@link CompositePermissionSubject} combines its sources, and it is
     * the default for {@link RoleAssignments#subject(Object)}.
     */
    PermissionResolutionPolicy ALLOW_OVERRIDES = (assignments, node, context) -> {
        for (RoleAssignment assignment : assignments) {
            if (assignment.role().permissions().hasPermission(node)) {
                return true;
            }
        }
        return false;
    };

    /**
     * Permitted if some applicable role permits the node and <b>no</b>
     * applicable role {@linkplain Role#denies(String) explicitly denies}
     * it: a deny rule in one role vetoes a grant in another, whichever
     * context each was assigned in. A role that simply does not mention
     * the node does not veto anything, and only a role built from rules
     * can deny.
     */
    PermissionResolutionPolicy DENY_OVERRIDES = (assignments, node, context) -> {
        boolean permitted = false;
        for (RoleAssignment assignment : assignments) {
            Role role = assignment.role();
            if (role.permissions().hasPermission(node)) {
                permitted = true;
            } else if (role.denies(node)) {
                return false;
            }
        }
        return permitted;
    };

    /**
     * Returns whether {@code assignments}, taken together, permit
     * {@code node} in {@code context}.
     *
     * @param assignments the target's assignments that apply to
     *                    {@code context}, oldest first; unmodifiable
     * @param node        a valid permission node
     * @param context     the context being checked, or {@code null} for none
     */
    boolean hasPermission(List<RoleAssignment> assignments, String node, String context);
}
