package pernorama.permission;

import pernorama.annotation.Perm;
import pernorama.annotation.PermGroup;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;

/**
 * Scans classes for {@link Perm} and {@link PermGroup} annotations and
 * keeps track of the resulting {@link PermissionNode}s.
 * <p>
 * A class annotated with {@link PermGroup} prefixes every {@link Perm}
 * declared on it (on the type itself or on its declared methods) with the
 * group name. A class without a {@link PermGroup} uses each {@link Perm}
 * value as-is, as a fully qualified node.
 * <p>
 * Only methods declared directly on the scanned class are considered;
 * inherited methods are not.
 */
public class PermissionRegistry {

    private final Map<String, PermissionNode> nodes = new LinkedHashMap<>();

    /**
     * Scans {@code type} for {@link PermGroup} and {@link Perm}
     * annotations and registers every permission node found.
     *
     * @return the permission nodes registered as a result of this call,
     *         in declaration order
     */
    public Set<PermissionNode> register(Class<?> type) {
        Objects.requireNonNull(type, "type");

        String groupPrefix = null;
        PermGroup group = type.getAnnotation(PermGroup.class);
        if (group != null) {
            groupPrefix = group.value();
        }

        Set<PermissionNode> registered = new LinkedHashSet<>();

        Perm typePerm = type.getAnnotation(Perm.class);
        if (typePerm != null) {
            registered.add(registerNode(resolve(groupPrefix, typePerm.value())));
        }

        for (Method method : type.getDeclaredMethods()) {
            Perm perm = method.getAnnotation(Perm.class);
            if (perm != null) {
                registered.add(registerNode(resolve(groupPrefix, perm.value())));
            }
        }

        return registered;
    }

    /** Looks up a previously registered node by its full dotted name. */
    public PermissionNode get(String node) {
        PermissionNode found = nodes.get(node);
        if (found == null) {
            throw new NoSuchElementException("Unknown permission node: '" + node + "'");
        }
        return found;
    }

    /** Returns {@code true} if a node with the given name is registered. */
    public boolean contains(String node) {
        return nodes.containsKey(node);
    }

    /** All permission nodes registered so far, in registration order. */
    public Collection<PermissionNode> all() {
        return Collections.unmodifiableCollection(nodes.values());
    }

    private String resolve(String groupPrefix, String value) {
        if (groupPrefix == null || groupPrefix.isBlank()) {
            return value;
        }
        return groupPrefix + "." + value;
    }

    private PermissionNode registerNode(String value) {
        PermissionNode node = PermissionNode.of(value);
        nodes.put(node.name(), node);
        return node;
    }
}
