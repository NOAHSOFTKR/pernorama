package pernorama.exception;

/**
 * Thrown when a string that is supposed to represent a permission node or
 * a permission pattern is syntactically invalid, e.g. blank, containing an
 * empty segment ({@code "users..create"}, {@code ".users"}, {@code "users."}),
 * or containing characters outside the allowed segment charset.
 * <p>
 * Raised in favor of a bare {@link IllegalArgumentException} so that callers
 * can distinguish "this is not a valid permission string" from other
 * argument-validation failures.
 */
public class InvalidPermissionException extends PernoramaException {

    private final String value;

    public InvalidPermissionException(String value) {
        super("Invalid permission: '" + value + "'");
        this.value = value;
    }

    /** The offending, syntactically invalid permission string. */
    public String value() {
        return value;
    }
}
