package pernorama.exception;

import pernorama.subject.PermissionSubject;

import java.util.Optional;

/**
 * Thrown when a {@link PermissionSubject} attempts an action that
 * requires a permission node it does not have.
 */
public class PermissionDeniedException extends PernoramaException {

    private final String requiredPermission;
    private final String context;
    private final transient PermissionSubject subject;

    /** For a permission that was required without a context. */
    public PermissionDeniedException(String requiredPermission, PermissionSubject subject) {
        this(requiredPermission, null, subject);
    }

    /**
     * For a permission that was required in {@code context}, or without
     * a context if it is {@code null}.
     */
    public PermissionDeniedException(String requiredPermission, String context, PermissionSubject subject) {
        super("Permission denied: " + requiredPermission + (context == null ? "" : " in context " + context));
        this.requiredPermission = requiredPermission;
        this.context = context;
        this.subject = subject;
    }

    /** The permission node that was required but missing. */
    public String requiredPermission() {
        return requiredPermission;
    }

    /** The context the permission was required in, if any. */
    public Optional<String> context() {
        return Optional.ofNullable(context);
    }

    /** The subject that lacked the required permission. */
    public PermissionSubject subject() {
        return subject;
    }
}
