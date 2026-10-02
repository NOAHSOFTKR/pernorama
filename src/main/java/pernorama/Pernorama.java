package pernorama;

import pernorama.permission.ContextPolicy;
import pernorama.role.MemoryRoleAssignmentStore;
import pernorama.role.RoleAssignmentStore;
import pernorama.role.RoleAssignments;
import pernorama.subject.MemoryPermissionSubject;

import java.util.Objects;

/**
 * The settings an application chooses once for all of its permission
 * checks, and the factory for the components that apply them:
 *
 * <pre>{@code
 * Pernorama pernorama = Pernorama.builder()
 *         .contextPolicy(ContextPolicy.EXACT)
 *         .build();
 *
 * MemoryPermissionSubject user = pernorama.newSubject();
 * RoleAssignments<String> assignments = pernorama.newRoleAssignments();
 * }</pre>
 *
 * Today the only setting is the {@link ContextPolicy}, which decides
 * whether a permission granted without a context also applies inside
 * one. It is instance-wide on purpose: individual permissions never
 * carry their own policy, and an application that needs different
 * semantics for different domains uses one instance per domain.
 * <p>
 * Pernorama never keeps an instance of its own; the application creates
 * one and passes it where it is needed. Everything created through an
 * instance uses its settings. A custom
 * {@link pernorama.subject.PermissionSubject} reads them from
 * {@link #contextPolicy()}.
 * <p>
 * Immutable and safe to share across threads.
 */
public final class Pernorama {

    private final ContextPolicy contextPolicy;

    private Pernorama(ContextPolicy contextPolicy) {
        this.contextPolicy = contextPolicy;
    }

    /**
     * Starts building an instance. Every setting has a default, so
     * {@code Pernorama.builder().build()} is a complete configuration.
     */
    public static Builder builder() {
        return new Builder();
    }

    /** The policy deciding which grants apply when a check names a context. */
    public ContextPolicy contextPolicy() {
        return contextPolicy;
    }

    /** A new, empty in-memory subject using this instance's settings. */
    public MemoryPermissionSubject newSubject() {
        return new MemoryPermissionSubject(contextPolicy);
    }

    /**
     * New role assignments, kept in a new {@link MemoryRoleAssignmentStore},
     * using this instance's settings.
     *
     * @param <K> how a target is identified, e.g. a user id
     */
    public <K> RoleAssignments<K> newRoleAssignments() {
        return newRoleAssignments(new MemoryRoleAssignmentStore<>());
    }

    /**
     * New role assignments kept in {@code store}, using this instance's
     * settings.
     *
     * @param <K> how a target is identified, e.g. a user id
     */
    public <K> RoleAssignments<K> newRoleAssignments(RoleAssignmentStore<K> store) {
        return new RoleAssignments<>(store, contextPolicy);
    }

    @Override
    public String toString() {
        return "Pernorama[contextPolicy=" + contextPolicy + "]";
    }

    /** Builder for {@link Pernorama}. Not thread-safe. */
    public static final class Builder {

        private ContextPolicy contextPolicy = ContextPolicy.GLOBAL_FALLBACK;

        private Builder() {
        }

        /**
         * Sets the policy deciding whether a grant without a context also
         * applies inside one. Defaults to
         * {@link ContextPolicy#GLOBAL_FALLBACK}.
         */
        public Builder contextPolicy(ContextPolicy contextPolicy) {
            this.contextPolicy = Objects.requireNonNull(contextPolicy, "contextPolicy");
            return this;
        }

        /** Builds the instance. */
        public Pernorama build() {
            return new Pernorama(contextPolicy);
        }
    }
}
