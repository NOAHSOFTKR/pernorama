package pernorama.subject;

import pernorama.permission.PermissionNode;
import pernorama.permission.PermissionResolver;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * An in-memory {@link PermissionSubject} backed by a set of granted
 * permission strings. Not thread-safe.
 */
public class MemoryPermissionSubject implements PermissionSubject {

    private final Set<String> grantedPermissions = new LinkedHashSet<>();

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

    /** The raw set of granted permission strings, in grant order. */
    public Set<String> grantedPermissions() {
        return Collections.unmodifiableSet(grantedPermissions);
    }

    private String normalize(String node) {
        if (!PermissionResolver.isValidPattern(node)) {
            throw new IllegalArgumentException("Invalid permission pattern: '" + node + "'");
        }
        return node;
    }
}
