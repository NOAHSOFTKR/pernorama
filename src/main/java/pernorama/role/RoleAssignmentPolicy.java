package pernorama.role;

import java.util.List;

/**
 * Decides what happens when assigning a role would take a target over
 * its {@link RoleGroup}'s {@link RoleGroup#maxAssignments() maximum}:
 * reject the assignment, or replace some of the roles the target already
 * holds in that group.
 * <p>
 * A policy is only consulted on overflow. Assigning a role the target
 * already holds is a no-op that never reaches it, and an assignment that
 * fits within the maximum simply happens.
 * <p>
 * This is only about which roles may coexist. How the permissions of
 * several held roles combine is a separate question, answered by
 * {@link PermissionResolutionPolicy}.
 *
 * <h2>Custom policies</h2>
 * Implement {@link #decide(RoleGroup, List, Role)} and pass the policy to
 * {@link RoleGroup.Builder#assignmentPolicy(RoleAssignmentPolicy)}. A
 * policy only decides; {@link RoleAssignments} checks the decision and
 * applies it as one atomic change. It throws
 * {@link IllegalStateException}, and changes nothing, if a decision
 * replaces a role the target does not hold in the group, still leaves the
 * target over the maximum, or takes it under the
 * {@link RoleGroup#minAssignments() minimum}. A policy may be called
 * more than once for one assignment if a concurrent change forces a
 * retry, so it should have no side effects.
 */
@FunctionalInterface
public interface RoleAssignmentPolicy {

    /** Rejects the assignment; the target keeps the roles it has. */
    RoleAssignmentPolicy REJECT = (group, held, requested) -> RoleAssignmentDecision.reject(
            "role group '" + group.id() + "' allows at most " + group.maxAssignments()
                    + " role(s) and the target already holds " + held.size());

    /**
     * Replaces every role the target holds in the group, so the new role
     * is the only one left. Meant for exclusive groups
     * ({@code maxAssignments(1)}), where it swaps one role for another;
     * in a larger group use {@link #REPLACE_OLDEST} or
     * {@link #REPLACE_NEWEST} to make room for just one. Because it
     * leaves a single role, a group with a
     * {@link RoleGroup#minAssignments() minimum} above {@code 1} cannot
     * use it; {@link RoleGroup.Builder#build()} rejects that combination.
     */
    RoleAssignmentPolicy REPLACE_EXISTING = (group, held, requested) -> RoleAssignmentDecision.replace(held);

    /** Replaces the roles the target has held longest, as few as needed to make room. */
    RoleAssignmentPolicy REPLACE_OLDEST = (group, held, requested) ->
            RoleAssignmentDecision.replace(held.subList(0, overflow(group, held)));

    /** Replaces the roles the target was given most recently, as few as needed to make room. */
    RoleAssignmentPolicy REPLACE_NEWEST = (group, held, requested) ->
            RoleAssignmentDecision.replace(held.subList(held.size() - overflow(group, held), held.size()));

    /**
     * Decides an assignment that would go over the group's maximum.
     *
     * @param group     the group of {@code requested}, whose limits apply
     * @param held      the roles the target holds in {@code group} in the
     *                  context being assigned in, oldest assignment first;
     *                  unmodifiable. Roles held in other contexts are not
     *                  counted and cannot be replaced.
     * @param requested the role being assigned, not in {@code held}
     * @return the decision; never {@code null}
     */
    RoleAssignmentDecision decide(RoleGroup group, List<Role> held, Role requested);

    /** How many held roles have to go for one more to fit. */
    private static int overflow(RoleGroup group, List<Role> held) {
        return Math.min(held.size(), held.size() - group.maxAssignments() + 1);
    }
}
