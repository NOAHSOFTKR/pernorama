package pernorama.permission;

import pernorama.exception.InvalidPermissionException;

import java.util.regex.Pattern;

/**
 * The single component responsible for permission node/pattern syntax
 * validation and for matching granted permission patterns against
 * required permission nodes, including the wildcard forms {@code "*"}
 * (matches everything) and {@code "users.*"} (matches {@code "users"} and
 * everything under it).
 * <p>
 * A wildcard segment is only meaningful as the final segment of a
 * pattern; it does not appear anywhere else. This keeps matching simple
 * and predictable.
 * <p>
 * {@link PermissionNode} delegates its own (non-wildcard) segment
 * validation here, so there is exactly one definition of what a valid
 * permission segment looks like.
 */
public final class PermissionResolver {

    private static final Pattern SEGMENT = Pattern.compile("[A-Za-z0-9_-]+");
    private static final String WILDCARD = "*";
    private static final String WILDCARD_SUFFIX = ".*";

    private PermissionResolver() {
    }

    /**
     * Returns {@code true} if {@code segment} is a valid single segment of
     * a permission node, i.e. one or more letters, digits, {@code _} or
     * {@code -}. Does not accept {@code "*"}; use {@link #isValidPattern}
     * for wildcard-aware validation.
     */
    static boolean isValidSegment(String segment) {
        return SEGMENT.matcher(segment).matches();
    }

    /**
     * Returns {@code true} if the given string is a syntactically valid
     * permission pattern: non-blank, dot-separated segments made of
     * letters, digits, {@code _} or {@code -}, optionally ending in a
     * single trailing {@code *} segment (or being {@code "*"} on its own).
     */
    public static boolean isValidPattern(String pattern) {
        if (pattern == null || pattern.isBlank()) {
            return false;
        }
        String[] segments = pattern.split("\\.", -1);
        for (int i = 0; i < segments.length; i++) {
            String segment = segments[i];
            boolean isLast = i == segments.length - 1;
            if (segment.equals(WILDCARD)) {
                if (!isLast) {
                    return false;
                }
                continue;
            }
            if (!isValidSegment(segment)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns {@code true} if the granted {@code pattern} covers the
     * {@code required} permission node.
     *
     * @throws InvalidPermissionException if {@code pattern} is not a
     *         valid permission pattern
     */
    public static boolean matches(String pattern, String required) {
        if (!isValidPattern(pattern)) {
            throw new InvalidPermissionException(pattern);
        }
        if (pattern.equals(WILDCARD)) {
            return true;
        }
        if (pattern.equals(required)) {
            return true;
        }
        if (pattern.endsWith(WILDCARD_SUFFIX)) {
            String prefix = pattern.substring(0, pattern.length() - WILDCARD_SUFFIX.length());
            return required.equals(prefix) || required.startsWith(prefix + ".");
        }
        return false;
    }

    /** Convenience overload of {@link #matches(String, String)}. */
    public static boolean matches(String pattern, PermissionNode required) {
        return matches(pattern, required.name());
    }

    /**
     * Returns {@code true} if any pattern in {@code patterns} covers the
     * {@code required} permission node.
     */
    public static boolean matchesAny(Iterable<String> patterns, String required) {
        for (String pattern : patterns) {
            if (matches(pattern, required)) {
                return true;
            }
        }
        return false;
    }
}
