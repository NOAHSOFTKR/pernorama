package pernorama.role;

import pernorama.exception.InvalidPermissionException;
import pernorama.permission.ContextPolicy;
import pernorama.permission.PermissionGrant;
import pernorama.permission.PermissionNode;
import pernorama.subject.PermissionSubject;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/**
 * Assigns {@link Role}s to targets, optionally in a context, enforcing
 * each role's {@link RoleGroup} constraints, and answers permission
 * checks from the roles a target holds.
 *
 * <pre>{@code
 * RoleAssignments<String> assignments = pernorama.newRoleAssignments();
 *
 * assignments.assign("alice", pro);                          // ASSIGNED
 * RoleAssignmentResult result = assignments.assign("alice", max5); // REPLACED, if the group is exclusive
 *
 * PermissionSubject alice = assignments.subject("alice");
 * alice.hasPermission("app.plan.max5"); // true
 * }</pre>
 *
 * <h2>Assigning</h2>
 * {@link #assign(Object, Role, String)} is idempotent: assigning a role
 * the target already holds in the same context returns
 * {@link RoleAssignmentStatus#NO_CHANGE} and never consults a policy.
 * Otherwise, if the role's group is already at its
 * {@link RoleGroup#maxAssignments() maximum}, the group's
 * {@link RoleAssignmentPolicy} decides whether to reject the assignment
 * or which held roles to replace. A role with no group is never limited.
 *
 * <h2>Contexts</h2>
 * Every operation takes an optional context, an opaque
 * application-defined string such as {@code "academy:123"}; each
 * overload without one is the same call with {@code null}, meaning no
 * context. One target can hold the same role in several contexts, and
 * each context is counted on its own: a group's limits apply to the
 * roles held in one context, so a target can be a teacher in
 * {@code academy:123} and a student in {@code academy:456} even if the
 * two roles share an exclusive group. Assignments without a context
 * are counted together, as one more context. A group id still has one
 * definition across every context: a held role carrying a conflicting
 * definition of the group fails the call wherever it is held.
 * <p>
 * Where an assignment applies is decided by the {@link ContextPolicy}
 * these assignments were created with, exactly as for a permission
 * granted in that context: under {@link ContextPolicy#GLOBAL_FALLBACK} a
 * role assigned without a context applies in every context, and under
 * {@link ContextPolicy#EXACT} only to checks without one. A role
 * assigned in a context applies to checks in exactly that context.
 *
 * <h2>Atomicity</h2>
 * Every call reads the target's assignments, works out the new list,
 * and writes it with one {@link RoleAssignmentStore#replace compare-and-set}.
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
    private final ContextPolicy contextPolicy;

    /**
     * Creates assignments kept in a new {@link MemoryRoleAssignmentStore},
     * using {@link ContextPolicy#GLOBAL_FALLBACK}.
     * {@link pernorama.Pernorama#newRoleAssignments()} uses your
     * application's policy instead.
     */
    public RoleAssignments() {
        this(new MemoryRoleAssignmentStore<>());
    }

    /** Creates assignments kept in {@code store}, using {@link ContextPolicy#GLOBAL_FALLBACK}. */
    public RoleAssignments(RoleAssignmentStore<K> store) {
        this(store, ContextPolicy.GLOBAL_FALLBACK);
    }

    /**
     * Creates assignments kept in {@code store}, applying
     * {@code contextPolicy}.
     * {@link pernorama.Pernorama#newRoleAssignments(RoleAssignmentStore)}
     * is the usual way to get one.
     */
    public RoleAssignments(RoleAssignmentStore<K> store, ContextPolicy contextPolicy) {
        this.store = Objects.requireNonNull(store, "store");
        this.contextPolicy = Objects.requireNonNull(contextPolicy, "contextPolicy");
    }

    /** {@link #assign(Object, Role, String)} without a context. */
    public RoleAssignmentResult assign(K target, Role role) {
        return assign(target, role, null);
    }

    /**
     * Assigns {@code role} to {@code target} in {@code context}, or
     * without a context if it is {@code null}. See the class
     * documentation for how group limits are applied.
     *
     * @return {@link RoleAssignmentStatus#ASSIGNED},
     *         {@link RoleAssignmentStatus#REPLACED},
     *         {@link RoleAssignmentStatus#NO_CHANGE} or
     *         {@link RoleAssignmentStatus#REJECTED}
     * @throws IllegalArgumentException if {@code context} is empty
     * @throws IllegalStateException if the group's policy returned a
     *         decision that breaks the group's constraints, or a held role
     *         carries a conflicting definition of the same group id; nothing
     *         is changed in either case
     */
    public RoleAssignmentResult assign(K target, Role role, String context) {
        Objects.requireNonNull(target, "target");
        RoleAssignment requested = new RoleAssignment(role, context);

        while (true) {
            List<RoleAssignment> current = assignmentsOf(target);
            if (current.contains(requested)) {
                return RoleAssignmentResult.noChange(role, context, true);
            }

            List<Role> removed = List.of();
            RoleGroup group = role.group().orElse(null);
            if (group != null) {
                List<Role> held = heldIn(current, group, context);
                if (held.size() >= group.maxAssignments()) {
                    RoleAssignmentDecision decision = Objects.requireNonNull(
                            group.assignmentPolicy().decide(group, held, role),
                            "assignment policy of group '" + group.id() + "' returned null");
                    if (decision.isRejected()) {
                        return RoleAssignmentResult.rejected(role, context, false,
                                decision.rejectionReason().orElseThrow());
                    }
                    removed = decision.replacedRoles();
                    checkReplacement(group, held, removed);
                }
            }

            List<RoleAssignment> updated = new ArrayList<>(current.size() + 1);
            for (RoleAssignment existing : current) {
                if (!(Objects.equals(existing.context(), context) && removed.contains(existing.role()))) {
                    updated.add(existing);
                }
            }
            updated.add(requested);

            if (store.replace(target, current, List.copyOf(updated))) {
                return removed.isEmpty()
                        ? RoleAssignmentResult.assigned(role, context)
                        : RoleAssignmentResult.replaced(role, context, removed);
            }
        }
    }

    /** {@link #unassign(Object, Role, String)} without a context. */
    public RoleAssignmentResult unassign(K target, Role role) {
        return unassign(target, role, null);
    }

    /**
     * Removes {@code role} from {@code target} in {@code context}, or the
     * assignment without a context if it is {@code null}; the same role
     * held in any other context is untouched. Rejected if it would leave
     * the target with fewer roles in the group, in that context, than the
     * group's {@link RoleGroup#minAssignments() minimum}.
     *
     * @return {@link RoleAssignmentStatus#UNASSIGNED},
     *         {@link RoleAssignmentStatus#NO_CHANGE} (the role was not
     *         held in that context) or {@link RoleAssignmentStatus#REJECTED}
     * @throws IllegalArgumentException if {@code context} is empty
     * @throws IllegalStateException if {@code role} or a held role carries
     *         a conflicting definition of the same group id; nothing is
     *         changed
     */
    public RoleAssignmentResult unassign(K target, Role role, String context) {
        Objects.requireNonNull(target, "target");
        RoleAssignment requested = new RoleAssignment(role, context);

        while (true) {
            List<RoleAssignment> current = assignmentsOf(target);
            int index = current.indexOf(requested);
            if (index < 0) {
                return RoleAssignmentResult.noChange(role, context, false);
            }

            // the stored role is the one whose group the target was counted against
            RoleGroup group = current.get(index).role().group().orElse(null);
            RoleGroup requestedGroup = role.group().orElse(null);
            if (group != null && requestedGroup != null && group.equals(requestedGroup)) {
                requireSameDefinition(group, requestedGroup, role);
            }
            if (group != null) {
                int remaining = heldIn(current, group, context).size() - 1;
                if (remaining < group.minAssignments()) {
                    return RoleAssignmentResult.rejected(role, context, true,
                            "role group '" + group.id() + "' requires at least " + group.minAssignments()
                                    + " role(s)" + (context == null ? "" : " in context " + context)
                                    + "; unassigning would leave " + remaining);
                }
            }

            List<RoleAssignment> updated = new ArrayList<>(current);
            updated.remove(index);

            if (store.replace(target, current, List.copyOf(updated))) {
                return RoleAssignmentResult.unassigned(role, context);
            }
        }
    }

    /** {@link #roles(Object, String)} without a context. */
    public List<Role> roles(K target) {
        return roles(target, null);
    }

    /**
     * The roles {@code target} holds in exactly {@code context} — or
     * without a context, if it is {@code null} — oldest assignment first.
     * This is what is held there, not what applies there: under
     * {@link ContextPolicy#GLOBAL_FALLBACK}, roles held without a context
     * also apply in {@code context} but are not listed.
     *
     * @throws IllegalArgumentException if {@code context} is empty
     */
    public List<Role> roles(K target, String context) {
        Objects.requireNonNull(target, "target");
        PermissionGrant.requireValidContext(context);
        List<Role> roles = new ArrayList<>();
        for (RoleAssignment assignment : assignmentsOf(target)) {
            if (Objects.equals(assignment.context(), context)) {
                roles.add(assignment.role());
            }
        }
        return List.copyOf(roles);
    }

    /** Every assignment {@code target} holds, in every context, oldest first. */
    public List<RoleAssignment> assignments(K target) {
        Objects.requireNonNull(target, "target");
        return assignmentsOf(target);
    }

    /** The policy deciding where an assignment in a context applies. */
    public ContextPolicy contextPolicy() {
        return contextPolicy;
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
     * with {@code policy} the roles whose assignments apply to the
     * context being checked. The subject is a live view: every
     * {@code hasPermission} call reads the target's current assignments,
     * so it reflects later changes. {@code grant} and {@code revoke}
     * throw {@link UnsupportedOperationException}; change the assignments
     * instead. To add permissions granted to the target directly, compose
     * this subject with its own in a
     * {@link pernorama.subject.CompositePermissionSubject}.
     */
    public PermissionSubject subject(K target, PermissionResolutionPolicy policy) {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(policy, "policy");
        return new AssignedRolesSubject<>(this, target, policy);
    }

    private List<RoleAssignment> assignmentsOf(K target) {
        return List.copyOf(Objects.requireNonNull(store.assignments(target), "store returned null assignments"));
    }

    /**
     * The roles in {@code assignments} held in {@code context} that belong
     * to {@code group}, failing if any of them carries a conflicting
     * definition of the same group id — otherwise the limits applied would
     * depend on which instance the caller happened to pass in.
     */
    private static List<Role> heldIn(List<RoleAssignment> assignments, RoleGroup group, String context) {
        List<Role> held = new ArrayList<>();
        for (RoleAssignment assignment : assignments) {
            Role role = assignment.role();
            RoleGroup other = role.group().orElse(null);
            if (other == null || !other.equals(group)) {
                continue;
            }
            requireSameDefinition(group, other, role);
            if (Objects.equals(assignment.context(), context)) {
                held.add(role);
            }
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
        public boolean hasPermission(String node, String context) {
            if (!PermissionNode.isValid(node)) {
                throw new InvalidPermissionException(node);
            }
            PermissionGrant.requireValidContext(context);
            List<RoleAssignment> applicable = new ArrayList<>();
            for (RoleAssignment assignment : assignments.assignmentsOf(target)) {
                if (assignments.contextPolicy.applies(assignment.context(), context)) {
                    applicable.add(assignment);
                }
            }
            return policy.hasPermission(List.copyOf(applicable), node, context);
        }

        @Override
        public void grant(String node, String context) {
            throw new UnsupportedOperationException(
                    "a role-assignment subject is read-only; assign a role instead");
        }

        @Override
        public void revoke(String node, String context) {
            throw new UnsupportedOperationException(
                    "a role-assignment subject is read-only; unassign a role instead");
        }

        @Override
        public String toString() {
            return "RoleAssignments.subject(" + target + ")";
        }
    }
}
