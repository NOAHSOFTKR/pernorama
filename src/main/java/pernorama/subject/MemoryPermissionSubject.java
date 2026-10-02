package pernorama.subject;

import pernorama.permission.ContextPolicy;
import pernorama.permission.PermissionGrant;

import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An in-memory {@link PermissionSubject} backed by a set of
 * {@linkplain PermissionGrant grants}: permission rules, which may
 * include deny rules such as {@code "-users.delete"}, each optionally
 * scoped to a context. {@link pernorama.permission.PermissionResolver}
 * decides which rule wins when several cover the same node, and the
 * subject's {@link ContextPolicy} decides which grants apply in a
 * context.
 * <p>
 * Create one with {@link pernorama.Pernorama#newSubject()} so it uses
 * the policy your application chose. The constructors that take no
 * policy use {@link ContextPolicy#GLOBAL_FALLBACK}, the default of
 * {@link pernorama.Pernorama#builder()}.
 * <p>
 * Thread-safe: {@link #grant(String, String)}, {@link #revoke(String, String)}
 * and {@link #hasPermission(String, String)} may all be called
 * concurrently from multiple threads without external synchronization.
 * The backing store is a {@link ConcurrentHashMap} key set, so reads
 * never block on writes. As with any concurrent collection, a
 * {@code hasPermission} call racing a {@code grant}/{@code revoke} call
 * on another thread may observe either the state before or after that
 * call; it never throws or corrupts state.
 * <p>
 * Each call is atomic on its own, but a rule set built from several
 * calls is not: between {@code grant("users.*")} and
 * {@code grant("-users.delete")} another thread can observe
 * {@code users.delete} as permitted, because the broad grant is already
 * in place and the deny rule that narrows it is not. The same applies
 * to {@link #MemoryPermissionSubject(Collection)}, which grants its
 * rules one at a time. Populate the subject before sharing it, or
 * synchronize a later multi-rule update yourself.
 */
public class MemoryPermissionSubject implements PermissionSubject {

    private final ContextPolicy contextPolicy;
    private final Set<PermissionGrant> grants = ConcurrentHashMap.newKeySet();

    /** Creates an empty subject using {@link ContextPolicy#GLOBAL_FALLBACK}. */
    public MemoryPermissionSubject() {
        this(ContextPolicy.GLOBAL_FALLBACK);
    }

    /**
     * Creates a subject using {@link ContextPolicy#GLOBAL_FALLBACK},
     * pre-granted with the given rules, without a context.
     */
    public MemoryPermissionSubject(Collection<String> initialPermissions) {
        this();
        initialPermissions.forEach(this::grant);
    }

    /**
     * Creates an empty subject that applies {@code contextPolicy}.
     * {@link pernorama.Pernorama#newSubject()} is the usual way to get
     * one.
     */
    public MemoryPermissionSubject(ContextPolicy contextPolicy) {
        this.contextPolicy = Objects.requireNonNull(contextPolicy, "contextPolicy");
    }

    @Override
    public boolean hasPermission(String node, String context) {
        return contextPolicy.permits(grants, node, context);
    }

    @Override
    public void grant(String node, String context) {
        grants.add(new PermissionGrant(node, context));
    }

    @Override
    public void revoke(String node, String context) {
        grants.remove(new PermissionGrant(node, context));
    }

    /**
     * Every grant this subject holds, deny rules and every context
     * included, as a read-only live view. Iteration order is not defined.
     */
    public Set<PermissionGrant> grants() {
        return Collections.unmodifiableSet(grants);
    }

    /** The policy deciding which grants apply in a context. */
    public ContextPolicy contextPolicy() {
        return contextPolicy;
    }
}
