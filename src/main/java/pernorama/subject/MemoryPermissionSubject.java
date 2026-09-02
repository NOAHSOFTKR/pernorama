package pernorama.subject;

import pernorama.exception.InvalidPermissionException;
import pernorama.permission.PermissionNode;
import pernorama.permission.PermissionResolver;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An in-memory {@link PermissionSubject} backed by a set of granted
 * permission strings.
 * <p>
 * Thread-safe: {@link #grant(String)}, {@link #revoke(String)} and
 * {@link #hasPermission(String)} may all be called concurrently from
 * multiple threads without external synchronization. The backing store is
 * a {@link ConcurrentHashMap} key set, so reads never block on writes.
 * As with any concurrent collection, a {@link #hasPermission(String)}
 * call racing a {@link #grant(String)}/{@link #revoke(String)} call on
 * another thread may observe either the state before or after that call;
 * it never throws or corrupts state.
 */
public class MemoryPermissionSubject implements PermissionSubject {

    private final Set<String> grantedPermissions = ConcurrentHashMap.newKeySet();

    public MemoryPermissionSubject() {
    }

    /** Creates a subject pre-granted with the given permission strings. */
    public MemoryPermissionSubject(Collection<String> initialPermissions) {
        initialPermissions.forEach(this::grant);
    }

    @Override
    public boolean hasPermission(String node) {
        PermissionNode required = PermissionNode.of(node);
        return PermissionResolver.matchesAny(grantedPermissions, required.name());
    }

    @Override
    public void grant(String node) {
        grantedPermissions.add(normalize(node));
    }

    @Override
    public void revoke(String node) {
        grantedPermissions.remove(normalize(node));
    }

    /**
     * The raw set of granted permission strings. Iteration order is not
     * defined.
     */
    public Set<String> grantedPermissions() {
        return Collections.unmodifiableSet(grantedPermissions);
    }

    private String normalize(String node) {
        if (!PermissionResolver.isValidPattern(node)) {
            throw new InvalidPermissionException(node);
        }
        return node;
    }
}
