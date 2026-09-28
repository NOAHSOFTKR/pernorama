package pernorama.role;

import java.util.Objects;

/**
 * Constraints shared by a set of related {@link Role}s: how many of them
 * one target may hold at once, and what happens when an assignment would
 * go over that limit.
 *
 * <pre>{@code
 * RoleGroup plan = RoleGroup.builder("plan")
 *         .maxAssignments(1)
 *         .assignmentPolicy(RoleAssignmentPolicy.REPLACE_EXISTING)
 *         .build();
 * }</pre>
 *
 * <h2>Cardinality</h2>
 * {@link #maxAssignments()} is enforced when a role is assigned: an
 * assignment that would take a target over it is handed to
 * {@link #assignmentPolicy()}, which either rejects it or names the
 * roles it replaces. {@link #minAssignments()} is enforced when a role
 * is unassigned: removing a role that would take a target under it is
 * rejected. A target that starts out under the minimum — every target
 * does, before its first assignment — is not an error; it just cannot
 * lose roles it needs to stay there.
 *
 * <h2>Identity</h2>
 * A group is identified by its {@link #id()}: two groups with the same
 * id are equal, and roles that point at either count against the same
 * limit. The limits and policy that apply to an assignment are the ones
 * on the group of the role being assigned.
 * <p>
 * Immutable and safe to share across threads.
 */
public final class RoleGroup {

    private final String id;
    private final int minAssignments;
    private final int maxAssignments;
    private final RoleAssignmentPolicy assignmentPolicy;

    private RoleGroup(Builder builder) {
        this.id = builder.id;
        this.minAssignments = builder.minAssignments;
        this.maxAssignments = builder.maxAssignments;
        this.assignmentPolicy = builder.assignmentPolicy;
    }

    /**
     * Starts building a group with the given id. Unless changed, a group
     * has no minimum, no maximum, and the {@link RoleAssignmentPolicy#REJECT}
     * policy.
     *
     * @throws IllegalArgumentException if {@code id} is null, blank, or has
     *         leading or trailing whitespace
     */
    public static Builder builder(String id) {
        return new Builder(RoleIds.requireValid(id, "group id"));
    }

    /** The id identifying this group. */
    public String id() {
        return id;
    }

    /** The fewest roles of this group a target may be left holding by an unassignment. */
    public int minAssignments() {
        return minAssignments;
    }

    /**
     * The most roles of this group a target may hold at once;
     * {@link Integer#MAX_VALUE} when unbounded.
     */
    public int maxAssignments() {
        return maxAssignments;
    }

    /** What happens when an assignment would go over {@link #maxAssignments()}. */
    public RoleAssignmentPolicy assignmentPolicy() {
        return assignmentPolicy;
    }

    @Override
    public boolean equals(Object o) {
        return this == o || (o instanceof RoleGroup other && id.equals(other.id));
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    @Override
    public String toString() {
        return id;
    }

    /** Builder for {@link RoleGroup}. Not thread-safe. */
    public static final class Builder {

        private final String id;
        private int minAssignments = 0;
        private int maxAssignments = Integer.MAX_VALUE;
        private RoleAssignmentPolicy assignmentPolicy = RoleAssignmentPolicy.REJECT;

        private Builder(String id) {
            this.id = id;
        }

        /** Sets the minimum; must be {@code >= 0}. Defaults to {@code 0}. */
        public Builder minAssignments(int minAssignments) {
            this.minAssignments = minAssignments;
            return this;
        }

        /** Sets the maximum; must be {@code >= 1}. Defaults to unbounded. */
        public Builder maxAssignments(int maxAssignments) {
            this.maxAssignments = maxAssignments;
            return this;
        }

        /** Sets the overflow policy. Defaults to {@link RoleAssignmentPolicy#REJECT}. */
        public Builder assignmentPolicy(RoleAssignmentPolicy assignmentPolicy) {
            this.assignmentPolicy = Objects.requireNonNull(assignmentPolicy, "assignmentPolicy");
            return this;
        }

        /**
         * Builds the group.
         *
         * @throws IllegalArgumentException if the minimum is negative, the
         *         maximum is less than {@code 1}, or the minimum is greater
         *         than the maximum, or the policy is
         *         {@link RoleAssignmentPolicy#REPLACE_EXISTING} with a
         *         minimum above {@code 1}, which it could never satisfy
         */
        public RoleGroup build() {
            if (minAssignments < 0) {
                throw new IllegalArgumentException("minAssignments must be >= 0: " + minAssignments);
            }
            if (maxAssignments < 1) {
                throw new IllegalArgumentException("maxAssignments must be >= 1: " + maxAssignments);
            }
            if (minAssignments > maxAssignments) {
                throw new IllegalArgumentException(
                        "minAssignments (" + minAssignments + ") must not exceed maxAssignments ("
                                + maxAssignments + ")");
            }
            if (assignmentPolicy == RoleAssignmentPolicy.REPLACE_EXISTING && minAssignments > 1) {
                throw new IllegalArgumentException(
                        "REPLACE_EXISTING leaves one role, below minAssignments (" + minAssignments
                                + "); use REPLACE_OLDEST or REPLACE_NEWEST");
            }
            return new RoleGroup(this);
        }
    }
}
