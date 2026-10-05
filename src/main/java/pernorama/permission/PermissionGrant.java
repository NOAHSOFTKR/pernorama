package pernorama.permission;

import pernorama.exception.InvalidPermissionException;

/**
 * One granted permission rule, optionally scoped to a context:
 *
 * <pre>{@code
 * new PermissionGrant("students.read", null);          // no context
 * new PermissionGrant("students.edit", "academy:123"); // only in academy:123
 * }</pre>
 *
 * The {@link #rule()} is anything {@link pernorama.subject.PermissionSubject#grant(String)}
 * accepts — a node, a wildcard, or either prefixed with {@code -} to deny.
 *
 * <h2>Contexts</h2>
 * A context is an opaque, application-defined string identifying the
 * scope in which a permission applies. Pernorama does not generate,
 * parse, validate, or interpret context values: {@code "academy:123"},
 * {@code "academy:*"} and {@code "academy"} are three unrelated strings,
 * compared only for equality.
 * <p>
 * The one rule Pernorama does apply is that "no context" has exactly one
 * spelling, {@code null}: the empty string is rejected rather than
 * treated as either a context or the absence of one. Whether a grant
 * with no context also applies inside a context is decided by the
 * {@link ContextPolicy}, not stored here.
 *
 * @param rule    a valid permission rule
 * @param context the context the rule is scoped to, or {@code null} for none
 */
public record PermissionGrant(String rule, String context) {

    /**
     * Creates a grant, validating both components.
     *
     * @throws InvalidPermissionException if {@code rule} is not a
     *         syntactically valid permission rule
     * @throws IllegalArgumentException if {@code context} is empty
     */
    public PermissionGrant {
        if (!PermissionResolver.isValidPattern(rule)) {
            throw new InvalidPermissionException(rule);
        }
        requireValidContext(context);
    }

    /** Whether this grant is scoped to a context. */
    public boolean hasContext() {
        return context != null;
    }

    /**
     * Returns {@code true} if {@code context} is acceptable wherever
     * Pernorama takes one: {@code null} (no context) or any non-empty
     * string.
     */
    public static boolean isValidContext(String context) {
        return context == null || !context.isEmpty();
    }

    /**
     * Returns {@code context} if it {@linkplain #isValidContext is valid}.
     *
     * @throws IllegalArgumentException if {@code context} is empty
     */
    public static String requireValidContext(String context) {
        if (!isValidContext(context)) {
            throw new IllegalArgumentException("context must be null or non-empty");
        }
        return context;
    }

    @Override
    public String toString() {
        return context == null ? rule : rule + " @ " + context;
    }
}
