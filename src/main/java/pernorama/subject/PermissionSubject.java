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
 *
 * <h2>Contexts</h2>
 * Every operation takes an optional <b>context</b>: an opaque,
 * application-defined string such as {@code "academy:123"} identifying
 * the scope a permission applies in. {@code null} means no context, and
 * each overload without a context parameter is exactly the same call
 * with {@code null}. Pernorama does not generate, parse, validate, or
 * interpret context values; whether a grant without a context also
 * applies inside one is decided by the
 * {@link pernorama.permission.ContextPolicy} in use. An implementation
 * only has to implement the three methods that take a context.
 *
 * <h2>Errors</h2>
 * Implementations are expected, but not required by the type system, to
 * throw {@link InvalidPermissionException} from {@link #grant(String, String)}
 * and {@link #revoke(String, String)} for a syntactically invalid rule,
 * to treat an invalid node passed to {@link #hasPermission(String, String)}
 * the same way, and to throw {@link IllegalArgumentException} for an
 * empty context. Whether an implementation is safe for concurrent use is
 * defined by that implementation; see {@link MemoryPermissionSubject} for
 * one that is.
 */
public interface PermissionSubject {

    /**
     * Returns {@code true} if this subject has the given permission in
     * {@code context}, or without a context if {@code context} is
     * {@code null}.
     *
     * @throws InvalidPermissionException if {@code node} is not a
     *         syntactically valid permission node
     * @throws IllegalArgumentException if {@code context} is empty
     */
    boolean hasPermission(String node, String context);

    /** {@link #hasPermission(String, String)} without a context. */
    default boolean hasPermission(String node) {
        return hasPermission(node, null);
    }

    /** Convenience overload of {@link #hasPermission(String, String)}. */
    default boolean hasPermission(PermissionNode node, String context) {
        return hasPermission(node.name(), context);
    }

    /** Convenience overload of {@link #hasPermission(String)}. */
    default boolean hasPermission(PermissionNode node) {
        return hasPermission(node.name(), null);
    }

    /**
     * Grants a permission rule to this subject, scoped to {@code context}
     * or to no context if it is {@code null}. {@code node} may be a
     * concrete node (e.g. {@code "users.create"}), a wildcard pattern
     * (e.g. {@code "users.*"} or {@code "*"}), or either of those
     * prefixed with {@code -} to deny instead of allow (e.g.
     * {@code "-users.delete"}). See
     * {@link pernorama.permission.PermissionResolver} for which rule
     * wins when several cover the same node.
     *
     * @throws InvalidPermissionException if {@code node} is not a
     *         syntactically valid permission rule
     * @throws IllegalArgumentException if {@code context} is empty
     */
    void grant(String node, String context);

    /** {@link #grant(String, String)} without a context. */
    default void grant(String node) {
        grant(node, null);
    }

    /** Convenience overload of {@link #grant(String, String)}. */
    default void grant(PermissionNode node, String context) {
        grant(node.name(), context);
    }

    /** Convenience overload of {@link #grant(String)}. */
    default void grant(PermissionNode node) {
        grant(node.name(), null);
    }

    /**
     * Revokes a previously granted rule. This removes an exact match of
     * a rule <b>and context</b> previously passed to
     * {@link #grant(String, String)}; it does not partially narrow a
     * broader wildcard grant, and it does not touch the same rule granted
     * in another context. For example, revoking {@code "users.create"}
     * after granting {@code "users.*"} has no effect — revoke
     * {@code "users.*"} itself, or grant the deny rule
     * {@code "-users.create"} to carve that one node out.
     *
     * @throws InvalidPermissionException if {@code node} is not a
     *         syntactically valid permission rule
     * @throws IllegalArgumentException if {@code context} is empty
     */
    void revoke(String node, String context);

    /** {@link #revoke(String, String)} without a context. */
    default void revoke(String node) {
        revoke(node, null);
    }

    /** Convenience overload of {@link #revoke(String, String)}. */
    default void revoke(PermissionNode node, String context) {
        revoke(node.name(), context);
    }

    /** Convenience overload of {@link #revoke(String)}. */
    default void revoke(PermissionNode node) {
        revoke(node.name(), null);
    }
}
