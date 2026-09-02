package pernorama.permission;

import pernorama.exception.PermissionDeniedException;
import pernorama.subject.PermissionSubject;

import java.util.Objects;

/**
 * Entry point for checking a permission node against a
 * {@link PermissionSubject} from plain Java code, without going through
 * {@link pernorama.interceptor.PermissionInterceptor} or an annotation.
 * <p>
 * Two styles are supported: {@link #check(PermissionSubject, String)}
 * returns a boolean for an if/else style check, while
 * {@link #require(PermissionSubject, String)} throws
 * {@link PermissionDeniedException} when the subject lacks the
 * permission, for a fail-fast guard-clause style.
 */
public final class Permission {

    private Permission() {
    }

    /**
     * Returns {@code true} if {@code subject} has {@code node}. Equivalent
     * to {@code subject.hasPermission(node)}; provided so callers that
     * otherwise only use {@link #require(PermissionSubject, String)} don't
     * need to import {@link PermissionSubject} just for this check.
     */
    public static boolean check(PermissionSubject subject, String node) {
        Objects.requireNonNull(subject, "subject");
        return subject.hasPermission(node);
    }

    /**
     * Throws {@link PermissionDeniedException} if {@code subject} does not
     * have {@code node}; otherwise returns normally.
     *
     * @throws PermissionDeniedException if {@code subject} lacks {@code node}
     */
    public static void require(PermissionSubject subject, String node) {
        Objects.requireNonNull(subject, "subject");
        if (!subject.hasPermission(node)) {
            throw new PermissionDeniedException(node, subject);
        }
    }
}
