package pernorama.role;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An in-memory {@link RoleAssignmentStore}, the default for
 * {@link RoleAssignments#RoleAssignments()}.
 * <p>
 * Thread-safe. Each target's assignments are held as an immutable list in a
 * {@link ConcurrentHashMap}, and {@link #replace(Object, List, List)}
 * compares and swaps it inside a single
 * {@link ConcurrentHashMap#compute compute}, so a reader always sees
 * either the whole list before a change or the whole list after it.
 *
 * @param <K> how a target is identified; needs proper
 *            {@code equals}/{@code hashCode}
 */
public final class MemoryRoleAssignmentStore<K> implements RoleAssignmentStore<K> {

    private final ConcurrentHashMap<K, List<RoleAssignment>> assignments = new ConcurrentHashMap<>();

    @Override
    public List<RoleAssignment> assignments(K target) {
        Objects.requireNonNull(target, "target");
        return assignments.getOrDefault(target, List.of());
    }

    @Override
    public boolean replace(K target, List<RoleAssignment> expected, List<RoleAssignment> updated) {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(expected, "expected");
        List<RoleAssignment> copy = List.copyOf(updated);
        boolean[] replaced = {false};
        assignments.compute(target, (key, current) -> {
            List<RoleAssignment> actual = current == null ? List.of() : current;
            if (!actual.equals(expected)) {
                return current;
            }
            replaced[0] = true;
            return copy.isEmpty() ? null : copy;
        });
        return replaced[0];
    }
}
