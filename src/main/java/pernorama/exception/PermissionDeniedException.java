package pernorama.exception;

import pernorama.subject.PermissionSubject;

/**
 * Thrown when a {@link PermissionSubject} attempts an action that
 * requires a permission node it does not have.
 */
public class PermissionDeniedException extends RuntimeException {

    private final String requiredPermission;
    private final transient PermissionSubject subject;

    public PermissionDeniedException(String requiredPermission, PermissionSubject subject) {
        super("Permission denied: " + requiredPermission);
        this.requiredPermission = requiredPermission;
        this.subject = subject;
    }

    /** The permission node that was required but missing. */
    public String requiredPermission() {
        return requiredPermission;
    }

    /** The subject that lacked the required permission. */
    public PermissionSubject subject() {
        return subject;
    }
}
