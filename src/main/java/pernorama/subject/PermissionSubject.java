package pernorama.subject;

import pernorama.exception.InvalidPermissionException;
import pernorama.permission.PermissionNode;

/**
 * Something that permissions can be granted to and checked against, e.g.
 * a user or a service account.
 * <p>
 * This is a storage-agnostic abstraction: an application is free to back
 * it with a database row, a JWT claim set, a Discord member's roles, or
 * anything else, by implementing this interface directly. Pernorama's
 * core module only ships {@link MemoryPermissionSubject} as a ready-made
 * in-memory implementation; it does not depend on any particular storage.
 * <p>
 * Implementations are expected, but not required by the type system, to
 * throw {@link InvalidPermissionException} from {@link #grant(String)}
 * and {@link #revoke(String)} for a syntactically invalid node, and to
 * treat an invalid node passed to {@link #hasPermission(String)} the same
 * way. Whether an implementation is safe for concurrent use is defined
 * by that implementation; see {@link MemoryPermissionSubject} for one
 * that is.
 */
public interface PermissionSubject {

    /**
     * Returns {@code true} if this subject has the given permission.
     *
     * @throws InvalidPermissionException if {@code node} is not a
     *         syntactically valid permission node
     */
    boolean hasPermission(String node);

    /** Convenience overload of {@link #hasPermission(String)}. */
    default boolean hasPermission(PermissionNode node) {
        return hasPermission(node.name());
    }

    /**
     * Grants a permission to this subject. {@code node} may be a
     * concrete node (e.g. {@code "users.create"}) or a wildcard pattern
     * (e.g. {@code "users.*"} or {@code "*"}).
     *
     * @throws InvalidPermissionException if {@code node} is not a
     *         syntactically valid permission node or pattern
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
     *
     * @throws InvalidPermissionException if {@code node} is not a
     *         syntactically valid permission node or pattern
     */
    void revoke(String node);

    /** Convenience overload of {@link #revoke(String)}. */
    default void revoke(PermissionNode node) {
        revoke(node.name());
    }
}
