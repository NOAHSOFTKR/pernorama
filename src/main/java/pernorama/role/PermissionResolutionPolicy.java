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
 * <p>
 * {@link pernorama.subject.PermissionSubject#explain(String, String) Explaining}
 * a check through a built-in policy reports the deciding layer and the
 * roles that decided it. A custom policy only returns its answer, so the
 * explanation lists the applicable roles, each with its own explanation,
 * with {@link pernorama.permission.PermissionExplanation.Provenance#PARTIAL
 * partial} provenance — unavailable if no role could be explained —
 * and none of them marked decisive.
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
            (assignments, node, context) -> RoleResolution.permits(assignments, node, context, false);

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
            (assignments, node, context) -> RoleResolution.permits(assignments, node, context, true);

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
