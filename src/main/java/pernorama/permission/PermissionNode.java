package pernorama.permission;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * An immutable, dot-separated permission identifier such as
 * {@code "users.create"}.
 * <p>
 * A {@code PermissionNode} always represents a concrete node; it does not
 * carry wildcard segments. Wildcard matching against granted patterns is
 * handled separately by {@link PermissionResolver}.
 */
public final class PermissionNode {

    private static final Pattern SEGMENT = Pattern.compile("[A-Za-z0-9_-]+");
    private static final String SEPARATOR = ".";

    private final String name;
    private final List<String> segments;

    private PermissionNode(List<String> segments) {
        this.segments = segments;
        this.name = String.join(SEPARATOR, segments);
    }

    /**
     * Parses the given dot-separated string into a {@code PermissionNode}.
     *
     * @throws IllegalArgumentException if the value is blank or contains
     *         an empty or invalid segment
     */
    public static PermissionNode of(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Permission node must not be blank");
        }
        String[] parts = value.split("\\.", -1);
        List<String> segments = new ArrayList<>(parts.length);
        for (String part : parts) {
            if (!SEGMENT.matcher(part).matches()) {
                throw new IllegalArgumentException("Invalid permission node: '" + value + "'");
            }
            segments.add(part);
        }
        return new PermissionNode(segments);
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
