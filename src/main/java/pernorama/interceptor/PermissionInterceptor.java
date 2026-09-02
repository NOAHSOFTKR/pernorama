package pernorama.interceptor;

import pernorama.annotation.Perm;
import pernorama.annotation.PermissionAnnotationResolver;
import pernorama.exception.PermissionDeniedException;
import pernorama.subject.PermissionSubject;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;

/**
 * Invokes methods on behalf of a {@link PermissionSubject}, enforcing any
 * {@link Perm} declared on the target method before it runs.
 * <p>
 * A method with no {@link Perm} annotation is invoked unconditionally.
 * Each invocation goes through three separate steps: resolving the
 * required permission from the method's annotations
 * ({@link PermissionAnnotationResolver}), evaluating it against the
 * subject ({@link PermissionSubject#hasPermission(String)}), and only
 * then reflectively invoking the method.
 */
public class PermissionInterceptor {

    /**
     * Looks up the method named {@code methodName} with {@code args.length}
     * parameters on {@code target}'s class and invokes it through
     * {@link #invoke(PermissionSubject, Object, Method, Object...)}.
     *
     * @throws NoSuchElementException if no matching method exists
     * @throws IllegalArgumentException if more than one method matches
     */
    public Object invoke(PermissionSubject subject, Object target, String methodName, Object... args) {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(methodName, "methodName");

        Method method = findMethod(target.getClass(), methodName, args.length);
        return invoke(subject, target, method, args);
    }

    /**
     * Invokes {@code method} on {@code target}, first throwing
     * {@link PermissionDeniedException} if {@code method} declares a
     * {@link Perm} that {@code subject} does not have.
     */
    public Object invoke(PermissionSubject subject, Object target, Method method, Object... args) {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(method, "method");

        Optional<String> permission = PermissionAnnotationResolver.resolve(method);
        if (permission.isPresent() && !subject.hasPermission(permission.get())) {
            throw new PermissionDeniedException(permission.get(), subject);
        }

        try {
            method.setAccessible(true);
            return method.invoke(target, args);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Failed to invoke " + method, e);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException re) {
                throw re;
            }
            if (cause instanceof Error er) {
                throw er;
            }
            throw new IllegalStateException("Failed to invoke " + method, cause);
        }
    }

    /**
     * Returns {@code true} if {@code subject} may invoke {@code method},
     * i.e. {@code method} has no {@link Perm} or {@code subject} has the
     * permission it declares.
     */
    public boolean isPermitted(PermissionSubject subject, Method method) {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(method, "method");

        Optional<String> permission = PermissionAnnotationResolver.resolve(method);
        return permission.isEmpty() || subject.hasPermission(permission.get());
    }

    private Method findMethod(Class<?> type, String methodName, int argCount) {
        List<Method> candidates = new ArrayList<>();
        for (Method method : type.getMethods()) {
            if (method.getName().equals(methodName) && method.getParameterCount() == argCount) {
                candidates.add(method);
            }
        }
        if (candidates.isEmpty()) {
            throw new NoSuchElementException(
                    "No method named '" + methodName + "' with " + argCount + " parameter(s) found on " + type);
        }
        if (candidates.size() > 1) {
            throw new IllegalArgumentException(
                    "Ambiguous method '" + methodName + "' with " + argCount + " parameter(s) found on " + type
                            + "; use invoke(subject, target, Method, args...) instead");
        }
        return candidates.get(0);
    }
}
