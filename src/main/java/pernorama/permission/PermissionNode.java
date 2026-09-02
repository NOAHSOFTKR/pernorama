package pernorama.permission;

import pernorama.exception.InvalidPermissionException;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * An immutable, dot-separated permission identifier such as
 * {@code "users.create"}.
 * <p>
 * A {@code PermissionNode} always represents a concrete node; it does not
 * carry wildcard segments. Wildcard matching against granted patterns is
 * handled separately by {@link PermissionResolver}, which is also the
 * single source of truth for what characters a segment may contain.
 */
public final class PermissionNode {

    private static final String SEPARATOR = ".";

    private final String name;
    private final List<String> segments;

    private PermissionNode(List<String> segments) {
        this.segments = segments;
        this.name = String.join(SEPARATOR, segments);
    }

    /**
     * Parses the given dot-separated string into a {@code PermissionNode}.
     * Wildcards ({@code "*"}, {@code "users.*"}) are not valid nodes; use
     * {@link PermissionResolver#isValidPattern(String)} to validate a
     * grantable pattern instead.
     *
     * @throws InvalidPermissionException if the value is blank or
     *         contains an empty or invalid segment
     */
    public static PermissionNode of(String value) {
        List<String> segments = parseSegments(value);
        if (segments == null) {
            throw new InvalidPermissionException(value);
        }
        return new PermissionNode(segments);
    }

    /**
     * Returns {@code true} if {@code value} would be accepted by
     * {@link #of(String)}, without throwing for invalid input.
     */
    public static boolean isValid(String value) {
        return parseSegments(value) != null;
    }

    /**
     * Splits and validates {@code value} in a single pass, or returns
     * {@code null} if it is blank or contains an invalid segment. The
     * sole implementation {@link #of(String)} and {@link #isValid(String)}
     * both build on, so they can never disagree on the same input.
     */
    private static List<String> parseSegments(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String[] parts = value.split("\\.", -1);
        List<String> segments = new ArrayList<>(parts.length);
        for (String part : parts) {
            if (!PermissionResolver.isValidSegment(part)) {
                return null;
            }
            segments.add(part);
        }
        return segments;
    }

    /** The full dotted node name, e.g. {@code "users.create"}. */
    public String name() {
        return name;
    }

    /** The individual dot-separated segments, e.g. {@code ["users", "create"]}. */
    public List<String> segments() {
        return segments;
    }

    /**
     * The parent node, e.g. the parent of {@code "users.create"} is
     * {@code "users"}. A top-level node such as {@code "users"} has no
     * parent.
     */
    public Optional<PermissionNode> parent() {
        if (segments.size() <= 1) {
            return Optional.empty();
        }
        return Optional.of(new PermissionNode(segments.subList(0, segments.size() - 1)));
    }

    /**
     * Returns {@code true} if this node is a descendant of {@code other},
     * i.e. {@code other}'s segments are a proper prefix of this node's
     * segments. A node is never a child of itself.
     */
    public boolean isChildOf(PermissionNode other) {
        Objects.requireNonNull(other, "other");
        List<String> otherSegments = other.segments;
        if (otherSegments.size() >= segments.size()) {
            return false;
        }
        return segments.subList(0, otherSegments.size()).equals(otherSegments);
    }

    /** Convenience overload of {@link #isChildOf(PermissionNode)}. */
    public boolean isChildOf(String other) {
        return isChildOf(PermissionNode.of(other));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof PermissionNode that)) {
            return false;
        }
        return name.equals(that.name);
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }

    @Override
    public String toString() {
        return name;
    }
}
