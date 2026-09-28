package pernorama.role;

import pernorama.exception.InvalidPermissionException;
import pernorama.permission.PermissionNode;
import pernorama.subject.PermissionSubject;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/**
 * Assigns {@link Role}s to targets, enforcing each role's
 * {@link RoleGroup} constraints, and answers permission checks from the
 * roles a target holds.
 *
 * <pre>{@code
 * RoleAssignments<String> assignments = new RoleAssignments<>();
 *
 * assignments.assign("alice", pro);                          // ASSIGNED
 * RoleAssignmentResult result = assignments.assign("alice", max5); // REPLACED, if the group is exclusive
 *
 * PermissionSubject alice = assignments.subject("alice");
 * alice.hasPermission("app.plan.max5"); // true
 * }</pre>
 *
 * <h2>Assigning</h2>
 * {@link #assign(Object, Role)} is idempotent: assigning a role the
 * target already holds returns {@link RoleAssignmentStatus#NO_CHANGE}
 * and never consults a policy. Otherwise, if the role's group is already
 * at its {@link RoleGroup#maxAssignments() maximum}, the group's
 * {@link RoleAssignmentPolicy} decides whether to reject the assignment
 * or which held roles to replace. A role with no group is never limited.
 *
 * <h2>Atomicity</h2>
 * Every call reads the target's roles, works out the new list, and
 * writes it with one {@link RoleAssignmentStore#replace compare-and-set}.
 * A replacement is therefore a single change: the target is seen holding
 * either the old role or the new one, never neither. If another call
 * changed the target in between, the whole decision is made again from
 * the fresh state, so a policy may be consulted more than once.
 *
 * <h2>Thread safety</h2>
 * Thread-safe as long as the store honors the
 * {@link RoleAssignmentStore} contract; {@link MemoryRoleAssignmentStore}
 * does.
 *
 * @param <K> how a target is identified, e.g. a user id
 */
public final class RoleAssignments<K> {

    private final RoleAssignmentStore<K> store;

    /** Creates assignments kept in a new {@link MemoryRoleAssignmentStore}. */
    public RoleAssignments() {
        this(new MemoryRoleAssignmentStore<>());
    }

    /** Creates assignments kept in {@code store}. */
    public RoleAssignments(RoleAssignmentStore<K> store) {
        this.store = Objects.requireNonNull(store, "store");
    }

    /**
     * Assigns {@code role} to {@code target}. See the class documentation
     * for how group limits are applied.
     *
     * @return {@link RoleAssignmentStatus#ASSIGNED},
     *         {@link RoleAssignmentStatus#REPLACED},
     *         {@link RoleAssignmentStatus#NO_CHANGE} or
     *         {@link RoleAssignmentStatus#REJECTED}
     * @throws IllegalStateException if the group's policy returned a
     *         decision that breaks the group's constraints, or a held role
     *         carries a conflicting definition of the same group id; nothing
     *         is changed in either case
     */
    public RoleAssignmentResult assign(K target, Role role) {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(role, "role");

        while (true) {
            List<Role> current = rolesOf(target);
            if (current.contains(role)) {
                return RoleAssignmentResult.noChange(role, true);
            }

            List<Role> removed = List.of();
            RoleGroup group = role.group().orElse(null);
            if (group != null) {
                List<Role> held = heldIn(current, group);
                if (held.size() >= group.maxAssignments()) {
                    RoleAssignmentDecision decision = Objects.requireNonNull(
                            group.assignmentPolicy().decide(group, held, role),
                            "assignment policy of group '" + group.id() + "' returned null");
                    if (decision.isRejected()) {
                        return RoleAssignmentResult.rejected(role, false, decision.rejectionReason().orElseThrow());
                    }
                    removed = decision.replacedRoles();
                    checkReplacement(group, held, removed);
                }
            }

            List<Role> updated = new ArrayList<>(current.size() + 1);
            for (Role existing : current) {
                if (!removed.contains(existing)) {
                    updated.add(existing);
                }
            }
            updated.add(role);

            if (store.replace(target, current, List.copyOf(updated))) {
                return removed.isEmpty()
                        ? RoleAssignmentResult.assigned(role)
                        : RoleAssignmentResult.replaced(role, removed);
            }
        }
    }

    /**
     * Removes {@code role} from {@code target}. Rejected if it would leave
     * the target with fewer roles in the group than the group's
     * {@link RoleGroup#minAssignments() minimum}.
     *
     * @return {@link RoleAssignmentStatus#UNASSIGNED},
     *         {@link RoleAssignmentStatus#NO_CHANGE} (the role was not
     *         held) or {@link RoleAssignmentStatus#REJECTED}
     * @throws IllegalStateException if {@code role} or a held role carries
     *         a conflicting definition of the same group id; nothing is
     *         changed
     */
    public RoleAssignmentResult unassign(K target, Role role) {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(role, "role");

        while (true) {
            List<Role> current = rolesOf(target);
            if (!current.contains(role)) {
                return RoleAssignmentResult.noChange(role, false);
            }

            // the stored role is the one whose group the target was counted against
            RoleGroup group = current.get(current.indexOf(role)).group().orElse(null);
            RoleGroup requestedGroup = role.group().orElse(null);
            if (group != null && requestedGroup != null && group.equals(requestedGroup)) {
                requireSameDefinition(group, requestedGroup, role);
            }
            if (group != null) {
                int remaining = heldIn(current, group).size() - 1;
                if (remaining < group.minAssignments()) {
                    return RoleAssignmentResult.rejected(role, true,
                            "role group '" + group.id() + "' requires at least " + group.minAssignments()
                                    + " role(s); unassigning would leave " + remaining);
                }
            }

            List<Role> updated = new ArrayList<>(current);
            updated.remove(role);

            if (store.replace(target, current, List.copyOf(updated))) {
                return RoleAssignmentResult.unassigned(role);
            }
        }
    }

    /** The roles {@code target} holds, oldest assignment first. */
    public List<Role> roles(K target) {
        Objects.requireNonNull(target, "target");
        return rolesOf(target);
    }

    /**
     * A read-only {@link PermissionSubject} for {@code target}, combining
     * its roles with {@link PermissionResolutionPolicy#ALLOW_OVERRIDES} —
     * the same semantics as {@link pernorama.subject.CompositePermissionSubject}.
     * See {@link #subject(Object, PermissionResolutionPolicy)}.
     */
    public PermissionSubject subject(K target) {
        return subject(target, PermissionResolutionPolicy.ALLOW_OVERRIDES);
    }

    /**
     * A read-only {@link PermissionSubject} for {@code target}, combining
     * its roles with {@code policy}. The subject is a live view: every
     * {@code hasPermission} call reads the target's current roles, so it
     * reflects later assignments. {@code grant} and {@code revoke} throw
     * {@link UnsupportedOperationException}; change the assignments
     * instead. To add permissions granted to the target directly, compose
     * this subject with its own in a
     * {@link pernorama.subject.CompositePermissionSubject}.
     */
    public PermissionSubject subject(K target, PermissionResolutionPolicy policy) {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(policy, "policy");
        return new AssignedRolesSubject<>(this, target, policy);
    }

    private List<Role> rolesOf(K target) {
        return List.copyOf(Objects.requireNonNull(store.roles(target), "store returned null roles"));
    }

    /**
     * The roles in {@code roles} that belong to {@code group}, failing if
     * any of them carries a conflicting definition of the same group id —
     * otherwise the limits applied would depend on which instance the
     * caller happened to pass in.
     */
    private static List<Role> heldIn(List<Role> roles, RoleGroup group) {
        List<Role> held = new ArrayList<>();
        for (Role role : roles) {
            RoleGroup other = role.group().orElse(null);
            if (other == null || !other.equals(group)) {
                continue;
            }
            requireSameDefinition(group, other, role);
            held.add(role);
        }
        return List.copyOf(held);
    }

    private static void requireSameDefinition(RoleGroup group, RoleGroup other, Role role) {
        if (!group.sameDefinition(other)) {
            throw new IllegalStateException("role group '" + group.id()
                    + "' has conflicting definitions: role '" + role.id() + "' was built with different "
                    + "limits or a different policy; build the group once and share it between its roles");
        }
    }

    /**
     * Checks a policy's replacement against the group before anything is
     * written, so a buggy custom policy fails loudly instead of leaving
     * the target in a state the group forbids.
     */
    private static void checkReplacement(RoleGroup group, List<Role> held, List<Role> removed) {
        if (new HashSet<>(removed).size() != removed.size()) {
            throw new IllegalStateException(
                    "assignment policy of group '" + group.id() + "' replaced a role twice: " + removed);
        }
        for (Role role : removed) {
            if (!held.contains(role)) {
                throw new IllegalStateException("assignment policy of group '" + group.id()
                        + "' replaced role '" + role.id() + "', which the target does not hold in that group");
            }
        }
        int after = held.size() - removed.size() + 1;
        if (after > group.maxAssignments()) {
            throw new IllegalStateException("assignment policy of group '" + group.id()
                    + "' leaves " + after + " role(s), over the maximum of " + group.maxAssignments());
        }
        if (after < group.minAssignments()) {
            throw new IllegalStateException("assignment policy of group '" + group.id()
                    + "' leaves " + after + " role(s), under the minimum of " + group.minAssignments());
        }
    }

    /** The live, read-only view returned by {@link #subject(Object, PermissionResolutionPolicy)}. */
    private static final class AssignedRolesSubject<K> implements PermissionSubject {

        private final RoleAssignments<K> assignments;
        private final K target;
        private final PermissionResolutionPolicy policy;

        private AssignedRolesSubject(RoleAssignments<K> assignments, K target, PermissionResolutionPolicy policy) {
            this.assignments = assignments;
            this.target = target;
            this.policy = policy;
        }

        @Override
        public boolean hasPermission(String node) {
            if (!PermissionNode.isValid(node)) {
                throw new InvalidPermissionException(node);
            }
            return policy.hasPermission(assignments.rolesOf(target), node);
        }

        @Override
        public void grant(String node) {
            throw new UnsupportedOperationException(
                    "a role-assignment subject is read-only; assign a role instead");
        }

        @Override
        public void revoke(String node) {
            throw new UnsupportedOperationException(
                    "a role-assignment subject is read-only; unassign a role instead");
        }

        @Override
        public String toString() {
            return "RoleAssignments.subject(" + target + ")";
        }
    }
}
