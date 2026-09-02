package pernorama.exception;

/**
 * Base type for every unchecked exception thrown by Pernorama.
 * <p>
 * A plain permission check ({@link pernorama.subject.PermissionSubject#hasPermission(String)})
 * never throws; this hierarchy only surfaces for programming errors (an
 * invalid permission string) or for the explicit "require" style of check
 * ({@link PermissionDeniedException}).
 */
public abstract class PernoramaException extends RuntimeException {

    protected PernoramaException(String message) {
        super(message);
    }

    protected PernoramaException(String message, Throwable cause) {
        super(message, cause);
    }
}
