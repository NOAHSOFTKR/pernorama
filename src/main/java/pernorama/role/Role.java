package pernorama.role;

import pernorama.exception.InvalidPermissionException;
import pernorama.permission.PermissionNode;
import pernorama.permission.PermissionResolver;
import pernorama.subject.PermissionSubject;

import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * A named, assignable bundle of permissions, optionally belonging to a
 * {@link RoleGroup}:
 *
 * <pre>{@code
 * Role pro = Role.builder("plan_pro")
 *         .group(plan)
 *         .permission("app.use")
 *         .permission("app.plan.pro")
 *         .build();
 * }</pre>
 *
 * A role is not itself a {@link PermissionSubject} — a subject is
 * whoever permissions are checked against (a user, a JWT principal, a
 * Discord member), and a role is only one thing such a subject can
 * draw permissions from. What a role permits is answered by
 * {@link #permissions()}, which uses the same rules, wildcards and deny
 * semantics as the rest of Pernorama; nothing here matches permissions
 * on its own.
 *
 * <h2>Where the permissions come from</h2>
 * A role is backed either by the rules passed to
 * {@link Builder#permission(String)}, which are evaluated with
 * {@link PermissionResolver#matchesAny(Iterable, String)}, or by an
 * existing subject passed to {@link Builder#permissions(PermissionSubject)}
 * — for example one loaded from your database. Not both.
 *
 * <h2>Identity</h2>
 * A role is identified by its {@link #id()}: two roles with the same id
 * are equal, whatever their permissions or group. Assignments are
 * stored and compared by role, so give each distinct role its own id.
 *
 * <h2>Definitions do not change under an assignment</h2>
 * A store keeps the {@code Role} instance it was given. Building a new
 * role with the same id but different rules or a different group does
 * not update targets that already hold it: assigning it is
 * {@link RoleAssignmentStatus#NO_CHANGE}, and those targets keep the old
 * definition. To change what a role permits without reassigning it,
 * back the role by a subject you update
 * ({@link Builder#permissions(PermissionSubject)}), or implement a
 * {@link RoleAssignmentStore} that stores role ids and resolves them
 * against your current definitions when it reads.
 * <p>
 * A role built from rules is immutable and safe to share across
 * threads. One backed by a subject is as thread-safe as that subject.
 */
public final class Role {

    private final String id;
    private final RoleGroup group;
    private final Set<String> rules;
    private final PermissionSubject permissions;

    private Role(String id, RoleGroup group, Set<String> rules, PermissionSubject permissions) {
        this.id = id;
        this.group = group;
        this.rules = rules;
        this.permissions = permissions;
    }

    /**
     * Starts building a role with the given id.
     *
     * @throws IllegalArgumentException if {@code id} is null, blank, or has
     *         leading or trailing whitespace
     */
    public static Builder builder(String id) {
        return new Builder(RoleIds.requireValid(id, "role id"));
    }

    /** The id identifying this role. */
    public String id() {
        return id;
    }

    /** The group this role belongs to, if any. */
    public Optional<RoleGroup> group() {
        return Optional.ofNullable(group);
    }

    /**
     * What this role permits. For a role built from rules this is a
     * read-only subject whose {@code grant}/{@code revoke} throw
     * {@link UnsupportedOperationException}; for a role built from a
     * subject it is that subject.
     */
    public PermissionSubject permissions() {
        return permissions;
    }

    /**
     * Returns {@code true} if this role <b>explicitly denies</b>
     * {@code node}: the rule that decides the node among this role's own
     * rules is a deny rule. That is different from not permitting it —
     * a node no rule covers is neither permitted nor denied.
     * <p>
     * Only a role built from rules can tell the two apart. A role backed
     * by a subject only exposes {@link PermissionSubject#hasPermission(String)},
     * so it never reports a denial.
     *
     * @throws InvalidPermissionException if {@code node} is not a
     *         syntactically valid permission node
     */
    public boolean denies(String node) {
        if (rules == null) {
            if (!PermissionNode.isValid(node)) {
                throw new InvalidPermissionException(node);
            }
            return false;
        }
        if (PermissionResolver.matchesAny(rules, node)) {
            return false;
        }
        for (String rule : rules) {
            if (PermissionResolver.denies(rule, node)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean equals(Object o) {
        return this == o || (o instanceof Role other && id.equals(other.id));
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    @Override
    public String toString() {
        return id;
    }

    /** Builder for {@link Role}. Not thread-safe. */
    public static final class Builder {

        private final String id;
        private RoleGroup group;
        private final Set<String> rules = new LinkedHashSet<>();
        private PermissionSubject source;

        private Builder(String id) {
            this.id = id;
        }

        /** Puts the role in {@code group}. */
        public Builder group(RoleGroup group) {
            this.group = Objects.requireNonNull(group, "group");
            return this;
        }

        /**
         * Adds a permission rule — a node, a wildcard, or either prefixed
         * with {@code -} to deny — exactly as
         * {@link PermissionSubject#grant(String)} accepts it.
         *
         * @throws InvalidPermissionException if {@code rule} is not a
         *         syntactically valid permission rule
         */
        public Builder permission(String rule) {
            if (!PermissionResolver.isValidPattern(rule)) {
                throw new InvalidPermissionException(rule);
            }
            rules.add(rule);
            return this;
        }

        /**
         * Backs the role by an existing subject instead of by rules, e.g.
         * one loaded from your own storage.
         */
        public Builder permissions(PermissionSubject source) {
            this.source = Objects.requireNonNull(source, "source");
            return this;
        }

        /**
         * Builds the role.
         *
         * @throws IllegalStateException if both rules and a backing
         *         subject were given
         */
        public Role build() {
            if (source != null) {
                if (!rules.isEmpty()) {
                    throw new IllegalStateException(
                            "role '" + id + "' has both rules and a backing subject; use one or the other");
                }
                return new Role(id, group, null, source);
            }
            Set<String> copy = Set.copyOf(rules);
            return new Role(id, group, copy, new RuleSubject(id, copy));
        }
    }

    /** The read-only subject behind a role built from rules. */
    private static final class RuleSubject implements PermissionSubject {

        private final String roleId;
        private final Set<String> rules;

        private RuleSubject(String roleId, Set<String> rules) {
            this.roleId = roleId;
            this.rules = rules;
        }

        @Override
        public boolean hasPermission(String node) {
            return PermissionResolver.matchesAny(rules, node);
        }

        @Override
        public void grant(String node) {
            throw new UnsupportedOperationException(
                    "role '" + roleId + "' is immutable; build a new role instead");
        }

        @Override
        public void revoke(String node) {
            throw new UnsupportedOperationException(
                    "role '" + roleId + "' is immutable; build a new role instead");
        }

        @Override
        public String toString() {
            return "Role[" + roleId + "]" + rules;
        }
    }
}
