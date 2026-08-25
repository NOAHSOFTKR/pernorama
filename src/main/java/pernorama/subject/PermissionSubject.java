package pernorama.subject;

import pernorama.permission.PermissionNode;

/**
 * Something that permissions can be granted to and checked against, e.g.
 * a user or a service account.
 */
public interface PermissionSubject {

    /** Returns {@code true} if this subject has the given permission. */
    boolean hasPermission(String node);

    /** Convenience overload of {@link #hasPermission(String)}. */
    default boolean hasPermission(PermissionNode node) {
        return hasPermission(node.name());
    }

    /**
     * Grants a permission to this subject. {@code node} may be a
     * concrete node (e.g. {@code "users.create"}) or a wildcard pattern
     * (e.g. {@code "users.*"} or {@code "*"}).
     */
    void grant(String node);

    /** Convenience overload of {@link #grant(String)}. */
    default void grant(PermissionNode node) {
        grant(node.name());
    }

    /**
     * Revokes a previously granted permission. This removes an exact
     * match of a string previously passed to {@link #grant(String)}; it
     * does not partially narrow a broader wildcard grant. For example,
     * revoking {@code "users.create"} after granting {@code "users.*"}
     * has no effect — revoke {@code "users.*"} itself instead.
     */
    void revoke(String node);

    /** Convenience overload of {@link #revoke(String)}. */
    default void revoke(PermissionNode node) {
        revoke(node.name());
    }
}
