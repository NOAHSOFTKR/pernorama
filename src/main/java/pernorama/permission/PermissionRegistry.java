package pernorama.permission;

import pernorama.annotation.Perm;
import pernorama.annotation.PermGroup;
import pernorama.annotation.PermissionAnnotationResolver;

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
 * keeps track of the resulting {@link PermissionNode}s as queryable
 * metadata (it does not itself grant or check anything; see
 * {@link pernorama.subject.PermissionSubject} and
 * {@link pernorama.permission.Permission} for that).
 * <p>
 * A class annotated with {@link PermGroup} prefixes every {@link Perm}
 * declared on it (on the type itself or on its declared methods) with the
 * group name. A class without a {@link PermGroup} uses each {@link Perm}
 * value as-is, as a fully qualified node.
 * <p>
 * Only methods declared directly on the scanned class are considered;
 * inherited methods are not. Method-level resolution follows the same
 * rule as {@link PermissionAnnotationResolver}.
 * <p>
 * <b>Duplicate registration is expected and safe.</b> The same permission
 * node commonly guards more than one method (e.g. {@code delete} and
 * {@code bulkDelete} both requiring {@code "users.delete"}), and
 * re-registering the same class (or two classes that happen to declare
 * the same node) simply leaves that node registered once; it is not
 * treated as an error.
 * <p>
 * Not thread-safe. A {@code PermissionRegistry} is normally populated
 * once at startup, on a single thread, before permission checks begin;
 * it is not meant to be mutated concurrently with lookups.
 */
public class PermissionRegistry {

    private final Map<String, PermissionNode> nodes = new LinkedHashMap<>();

    /**
     * Scans {@code type} for {@link PermGroup} and {@link Perm}
     * annotations and registers every permission node found. Safe to
     * call more than once, including with a class already scanned; nodes
     * already known are simply not duplicated.
     *
     * @return the permission nodes found on {@code type}, in declaration
     *         order (including ones that were already registered before
     *         this call)
     */
    public Set<PermissionNode> register(Class<?> type) {
        Objects.requireNonNull(type, "type");

        PermGroup group = type.getAnnotation(PermGroup.class);
        String groupPrefix = group != null ? group.value() : null;

        Set<PermissionNode> registered = new LinkedHashSet<>();

        Perm typePerm = type.getAnnotation(Perm.class);
        if (typePerm != null) {
            registered.add(registerNode(PermissionAnnotationResolver.combine(groupPrefix, typePerm.value())));
        }

        for (Method method : type.getDeclaredMethods()) {
            PermissionAnnotationResolver.resolve(method)
                    .ifPresent(node -> registered.add(registerNode(node)));
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

    /**
     * Returns {@code true} if {@code node} is both a syntactically valid
     * permission node and currently registered. Unlike {@link #get(String)}
     * and {@link #contains(String)}, this never throws for a malformed
     * input; it simply returns {@code false}.
     */
    public boolean validate(String node) {
        return PermissionNode.isValid(node) && contains(node);
    }

    /** All permission nodes registered so far, in registration order. */
    public Collection<PermissionNode> all() {
        return Collections.unmodifiableCollection(nodes.values());
    }

    private PermissionNode registerNode(String value) {
        return nodes.computeIfAbsent(value, ignored -> PermissionNode.of(value));
    }
}
