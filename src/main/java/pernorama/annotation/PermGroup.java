package pernorama.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Groups the {@link Perm}-annotated methods declared in the annotated
 * type under a common permission node prefix.
 * <p>
 * For example, a type annotated with {@code @PermGroup("users")} that
 * declares a method annotated with {@code @Perm("create")} yields the
 * final permission node {@code "users.create"}.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface PermGroup {

    /**
     * The group name, used as the prefix for permission nodes declared
     * by methods within the annotated type.
     */
    String value();
}
