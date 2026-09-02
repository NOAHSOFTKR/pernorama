package pernorama.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares a permission node required to execute the annotated method,
 * or defines a permission node for the annotated type.
 * <p>
 * When used inside a class annotated with {@link PermGroup}, the value
 * declared here is treated as relative to the group name, and the two
 * are joined with {@code "."} to form the final permission node.
 * <p>
 * {@code @Perm} on a method is not inherited by an overriding method; see
 * {@link PermissionAnnotationResolver} for the exact resolution rule.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface Perm {

    /**
     * The permission node string, e.g. {@code "users.create"} or,
     * when nested under a {@link PermGroup}, a relative segment such
     * as {@code "create"}.
     */
    String value();
}
