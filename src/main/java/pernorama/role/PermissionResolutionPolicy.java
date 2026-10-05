package pernorama.role;

import pernorama.permission.PermissionResolver;
import pernorama.subject.CompositePermissionSubject;

import java.util.List;
import java.util.Objects;

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
 *
 * <h2>Context first</h2>
 * Under {@link pernorama.permission.ContextPolicy#GLOBAL_FALLBACK} a check
 * in a context can see roles held in that context and roles held without
 * one. The built-in policies treat them as two layers, exactly as
 * {@link pernorama.permission.ContextPolicy#permits ContextPolicy.permits}
 * treats grants: if any role held in the checked context permits or
 * explicitly denies the node, those roles decide, and the roles held
 * without a context decide only otherwise. So a role held in
 * {@code academy:123} can narrow, or re-allow, what a global role says
 * about a node, in {@code academy:123} only. A check without a context,
 * or one under {@link pernorama.permission.ContextPolicy#EXACT}, has a
 * single layer.
 * <p>
 * Which roles a target may hold together is a separate question,
 * answered by {@link RoleAssignmentPolicy}.
 * <p>
 * Implement this interface for a combination the built-in policies do
 * not cover — one that ranks roles by their group, say. A custom policy
 * receives every applicable assignment, from both layers, and decides
 * for itself how they relate. The node and context passed in have
 * already been validated.
 */
@FunctionalInterface
public interface PermissionResolutionPolicy {

    /**
     * Permitted if <b>any</b> role in the deciding layer permits the
     * node. A deny rule only limits the role holding it within its layer,
     * which is exactly how {@link CompositePermissionSubject} combines its
     * sources; across layers, a role held in the checked context that
     * denies the node still decides it (see the class documentation).
     * This is the default for {@link RoleAssignments#subject(Object)}.
     */
    PermissionResolutionPolicy ALLOW_OVERRIDES =
            (assignments, node, context) -> layered(assignments, node, context, false);

    /**
     * Permitted if some role in the deciding layer permits the node and
     * <b>no</b> role in it {@linkplain Role#denies(String) explicitly
     * denies} it: a deny rule in one role vetoes a grant in another held
     * in the same layer. A role held in the checked context therefore
     * outranks a role held without one, in either direction (see the
     * class documentation). A role that simply does not mention the node
     * does not veto anything, and only a role built from rules can deny.
     */
    PermissionResolutionPolicy DENY_OVERRIDES =
            (assignments, node, context) -> layered(assignments, node, context, true);

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

    /**
     * The context-first layering shared by the built-in policies: decides
     * the layer of roles held in exactly {@code context} first, and the
     * rest — the roles held without a context that apply to it — only if
     * the first layer does not cover {@code node}.
     */
    private static boolean layered(
            List<RoleAssignment> assignments, String node, String context, boolean denyOverrides) {
        PermissionResolver.Decision decision = decideLayer(assignments, node, context, true, denyOverrides);
        if (decision == PermissionResolver.Decision.NOT_COVERED) {
            decision = decideLayer(assignments, node, context, false, denyOverrides);
        }
        return decision == PermissionResolver.Decision.PERMITTED;
    }

    /**
     * The decision of one layer: the assignments held in {@code context}
     * if {@code scoped}, otherwise those held without a context. An
     * assignment held in some other context belongs to neither, even if
     * a caller passes one in. Under {@code denyOverrides}
     * any denial decides the layer; otherwise any permission does. A
     * layer in which no role covers the node is
     * {@link PermissionResolver.Decision#NOT_COVERED}.
     */
    private static PermissionResolver.Decision decideLayer(
            List<RoleAssignment> assignments, String node, String context, boolean scoped, boolean denyOverrides) {
        boolean permitted = false;
        boolean denied = false;
        for (RoleAssignment assignment : assignments) {
            boolean inContext = Objects.equals(assignment.context(), context);
            if (scoped ? !inContext : inContext || assignment.context() != null) {
                continue;
            }
            switch (assignment.role().decide(node)) {
                case PERMITTED -> {
                    if (!denyOverrides) {
                        return PermissionResolver.Decision.PERMITTED;
                    }
                    permitted = true;
                }
                case DENIED -> {
                    if (denyOverrides) {
                        return PermissionResolver.Decision.DENIED;
                    }
                    denied = true;
                }
                case NOT_COVERED -> {
                }
            }
        }
        if (permitted) {
            return PermissionResolver.Decision.PERMITTED;
        }
        return denied ? PermissionResolver.Decision.DENIED : PermissionResolver.Decision.NOT_COVERED;
    }
}
