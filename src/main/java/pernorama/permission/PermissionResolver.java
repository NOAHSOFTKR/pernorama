package pernorama.permission;

import pernorama.exception.InvalidPermissionException;

import java.util.regex.Pattern;

/**
 * The single component responsible for permission node/pattern syntax
 * validation and for deciding whether a set of granted permission rules
 * permits a required permission node.
 *
 * <h2>Rules</h2>
 * A rule is either an <b>allow</b> rule or a <b>deny</b> rule:
 * <ul>
 *   <li>{@code "users.create"} allows exactly that node.</li>
 *   <li>{@code "users.*"} allows {@code "users"} and everything under
 *       it. A wildcard segment is only meaningful as the final segment
 *       of a rule; {@code "users.*.read"} is not a valid rule.</li>
 *   <li>{@code "*"} allows every permission.</li>
 *   <li>A leading {@code -} makes the same forms deny instead of allow:
 *       {@code "-users.delete"}, {@code "-users.*"}, {@code "-*"}.</li>
 * </ul>
 *
 * <h2>Which rule wins</h2>
 * {@link #matchesAny(Iterable, String)} evaluates a whole set of rules
 * against one required node: <b>the most specific rule that covers the
 * node decides</b>, and a deny rule wins a tie. Specificity is, in
 * order:
 * <ol>
 *   <li>an exact rule ({@code "users.delete"}) beats a wildcard rule
 *       that also covers the node;</li>
 *   <li>between two wildcard rules, the one with more segments before
 *       the {@code *} wins ({@code "users.profile.*"} beats
 *       {@code "users.*"}, which beats {@code "*"}).</li>
 * </ol>
 * So {@code ["users.*", "-users.delete"]} permits {@code users.create}
 * but not {@code users.delete}, and {@code ["-users.*", "users.read"]}
 * permits {@code users.read} and nothing else under {@code users}.
 * A node that no rule covers is not permitted.
 * <p>
 * An exact rule covers exactly its own node, and that holds for deny
 * rules too: {@code "-users.delete"} does not deny
 * {@code "users.delete.hard"}, which the surrounding {@code "users.*"}
 * still permits. Deny the subtree with {@code "-users.delete.*"}, which
 * covers {@code users.delete} and everything under it.
 *
 * <h2>Node syntax</h2>
 * {@link PermissionNode} delegates its own (non-wildcard) validation
 * here, so there is exactly one definition of what a valid permission
 * segment looks like. Because a leading {@code -} marks a deny rule, a
 * permission node itself may never start with {@code -}; the character
 * remains legal anywhere else ({@code "users.soft-delete"}).
 */
public final class PermissionResolver {

    private static final Pattern SEGMENT = Pattern.compile("[A-Za-z0-9_-]+");
    private static final String WILDCARD = "*";
    private static final String WILDCARD_SUFFIX = ".*";
    private static final char DENY_PREFIX = '-';

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
     * Returns {@code true} if {@code value} starts with the deny prefix
     * {@code -}, i.e. it is meant as a deny rule rather than a node.
     * Says nothing about whether the rest of it is valid.
     */
    static boolean isDeny(String value) {
        return value != null && !value.isEmpty() && value.charAt(0) == DENY_PREFIX;
    }

    /**
     * Returns {@code true} if the given string is a syntactically valid
     * permission rule: non-blank, dot-separated segments made of letters,
     * digits, {@code _} or {@code -}, optionally ending in a single
     * trailing {@code *} segment (or being {@code "*"} on its own), and
     * optionally prefixed with a single {@code -} to deny rather than
     * allow.
     */
    public static boolean isValidPattern(String pattern) {
        if (pattern == null || pattern.isBlank()) {
            return false;
        }
        return isValidAllowPattern(isDeny(pattern) ? pattern.substring(1) : pattern);
    }

    /**
     * Returns {@code true} if {@code pattern} is an <b>allow</b> rule that
     * covers the {@code required} permission node. A deny rule never
     * allows anything, so this returns {@code false} for one; use
     * {@link #denies(String, String)} to test a deny rule, or
     * {@link #matchesAny(Iterable, String)} to evaluate a whole rule set.
     *
     * @throws InvalidPermissionException if {@code pattern} is not a
     *         valid permission rule, or {@code required} is not a valid
     *         permission node
     */
    public static boolean matches(String pattern, String required) {
        validateRule(pattern);
        validateNode(required);
        return !isDeny(pattern) && specificity(pattern, required) >= 0;
    }

    /** Convenience overload of {@link #matches(String, String)}. */
    public static boolean matches(String pattern, PermissionNode required) {
        return matches(pattern, required.name());
    }

    /**
     * Returns {@code true} if {@code pattern} is a <b>deny</b> rule that
     * covers the {@code required} permission node. The mirror image of
     * {@link #matches(String, String)}: an allow rule never denies
     * anything, so this returns {@code false} for one.
     *
     * @throws InvalidPermissionException if {@code pattern} is not a
     *         valid permission rule, or {@code required} is not a valid
     *         permission node
     */
    public static boolean denies(String pattern, String required) {
        validateRule(pattern);
        validateNode(required);
        return isDeny(pattern) && specificity(pattern.substring(1), required) >= 0;
    }

    /** Convenience overload of {@link #denies(String, String)}. */
    public static boolean denies(String pattern, PermissionNode required) {
        return denies(pattern, required.name());
    }

    /**
     * Returns {@code true} if the rules in {@code patterns} permit the
     * {@code required} permission node, applying the precedence described
     * in the class documentation: the most specific covering rule
     * decides, a deny rule wins a tie, and a node no rule covers is not
     * permitted.
     * <p>
     * Every rule is examined, so an invalid rule anywhere in
     * {@code patterns} is reported even when an earlier rule already
     * covers the node. {@code required} is validated as a node, which is
     * what keeps a caller from asking about something that is not one —
     * {@code "-users.read"} or {@code "users.*"} — and stepping around a
     * deny rule that way.
     *
     * @throws InvalidPermissionException if any rule in {@code patterns}
     *         is not a valid permission rule, or {@code required} is not
     *         a valid permission node
     */
    public static boolean matchesAny(Iterable<String> patterns, String required) {
        validateNode(required);

        int best = -1;
        boolean permitted = false;

        for (String pattern : patterns) {
            validateRule(pattern);
            boolean deny = isDeny(pattern);
            int score = specificity(deny ? pattern.substring(1) : pattern, required);
            if (score < 0) {
                continue;
            }
            if (score > best) {
                best = score;
                permitted = !deny;
            } else if (score == best && deny) {
                permitted = false;
            }
        }

        return permitted;
    }

    private static void validateRule(String pattern) {
        if (!isValidPattern(pattern)) {
            throw new InvalidPermissionException(pattern);
        }
    }

    private static void validateNode(String required) {
        if (!PermissionNode.isValid(required)) {
            throw new InvalidPermissionException(required);
        }
    }

    /**
     * Validates a rule with any deny prefix already stripped: the same
     * syntax an allow rule uses, which is also what a deny rule has to
     * wrap. A second leading {@code -} is rejected here rather than read
     * as part of a segment, so {@code "--users"} is not a rule.
     */
    private static boolean isValidAllowPattern(String pattern) {
        if (pattern.isBlank() || isDeny(pattern)) {
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
     * How specific {@code rule} — a valid rule with any deny prefix
     * already stripped — is for {@code required}, or {@code -1} if it
     * does not cover it at all. Higher wins; an exact rule scores above
     * every wildcard rule that covers the same node, and a longer
     * wildcard prefix scores above a shorter one.
     */
    private static int specificity(String rule, String required) {
        if (rule.equals(WILDCARD)) {
            return 0;
        }
        if (rule.equals(required)) {
            return 2 * segmentCount(rule) + 1;
        }
        if (rule.endsWith(WILDCARD_SUFFIX)) {
            String prefix = rule.substring(0, rule.length() - WILDCARD_SUFFIX.length());
            if (required.equals(prefix) || required.startsWith(prefix + ".")) {
                return 2 * segmentCount(prefix);
            }
        }
        return -1;
    }

    private static int segmentCount(String value) {
        int count = 1;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '.') {
                count++;
            }
        }
        return count;
    }
}
