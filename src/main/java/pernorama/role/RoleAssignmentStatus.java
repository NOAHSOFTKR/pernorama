package pernorama.role;

/** The outcome of a {@link RoleAssignments} operation. */
public enum RoleAssignmentStatus {

    /** The role was added and nothing was removed. */
    ASSIGNED,

    /** The role was added and one or more held roles were removed in the same change. */
    REPLACED,

    /** The role was removed. */
    UNASSIGNED,

    /**
     * Nothing changed because the target was already in the requested
     * state: it already held the role being assigned, or did not hold
     * the role being unassigned.
     */
    NO_CHANGE,

    /** Nothing changed because the operation would have broken a group constraint. */
    REJECTED
}
