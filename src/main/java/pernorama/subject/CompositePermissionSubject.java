package pernorama.subject;

import pernorama.exception.InvalidPermissionException;
import pernorama.permission.PermissionNode;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * A read-only {@link PermissionSubject} that answers from several other
 * subjects at once — the usual "a user holds roles, and each role
 * carries permissions" shape:
 *
 * <pre>{@code
 * PermissionSubject admins = new MemoryPermissionSubject(List.of("users.*"));
 * PermissionSubject own = new MemoryPermissionSubject(List.of("profile.edit"));
 *
 * PermissionSubject user = new CompositePermissionSubject(own, admins);
 * user.hasPermission("users.create"); // true, from the admins role
 * user.hasPermission("profile.edit"); // true, from the user's own grants
 * }</pre>
 *
 * <h2>How the answer is combined</h2>
 * {@link #hasPermission(String)} is {@code true} if <b>any</b> source
 * says {@code true}. Each source evaluates its own rules on its own,
 * including any deny rules it holds, so <b>a deny rule only limits the
 * source that holds it</b>: if one role denies {@code users.delete} but
 * another source grants it, the answer is {@code true}. Put a permission
 * in fewer sources rather than expecting a deny in one source to
 * override another. A composite with no sources permits nothing.
 *
 * <h2>Read-only</h2>
 * {@link #grant(String)} and {@link #revoke(String)} throw
 * {@link UnsupportedOperationException}: a composite has no storage of
 * its own, and silently picking one of the sources to write to would
 * make "granted to the role" and "granted to the user" indistinguishable
 * at the call site. Modify the source you actually mean instead.
 *
 * <h2>Thread safety</h2>
 * The composite itself is immutable: the source list is copied when it
 * is constructed and never changes. Whether concurrent use is safe
 * therefore depends entirely on the sources it was given; see
 * {@link MemoryPermissionSubject} for one that is safe.
 */
public final class CompositePermissionSubject implements PermissionSubject {

    private final List<PermissionSubject> sources;

    /** Creates a composite over the given subjects, consulted in order. */
    public CompositePermissionSubject(PermissionSubject... sources) {
        this(Arrays.asList(Objects.requireNonNull(sources, "sources")));
    }

    /** Creates a composite over the given subjects, consulted in iteration order. */
    public CompositePermissionSubject(Collection<? extends PermissionSubject> sources) {
        Objects.requireNonNull(sources, "sources");
        List<PermissionSubject> copy = new ArrayList<>(sources.size());
        for (PermissionSubject source : sources) {
            copy.add(Objects.requireNonNull(source, "source"));
        }
        this.sources = List.copyOf(copy);
    }

    /**
     * Returns {@code true} if any source has {@code node}. Sources are
     * consulted in order and the first {@code true} wins, so a source
     * that would have thrown is not necessarily reached.
     *
     * @throws InvalidPermissionException if {@code node} is not a
     *         syntactically valid permission node
     */
    @Override
    public boolean hasPermission(String node) {
        if (!PermissionNode.isValid(node)) {
            throw new InvalidPermissionException(node);
        }
        for (PermissionSubject source : sources) {
            if (source.hasPermission(node)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Always throws: a composite is read-only.
     *
     * @throws UnsupportedOperationException always
     */
    @Override
    public void grant(String node) {
        throw new UnsupportedOperationException(
                "CompositePermissionSubject is read-only; grant on the source subject instead");
    }

    /**
     * Always throws: a composite is read-only.
     *
     * @throws UnsupportedOperationException always
     */
    @Override
    public void revoke(String node) {
        throw new UnsupportedOperationException(
                "CompositePermissionSubject is read-only; revoke on the source subject instead");
    }

    /** The subjects this composite consults, in the order it consults them. */
    public List<PermissionSubject> sources() {
        return sources;
    }
}
