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
     * Returns {@code true} if {@code subject} has {@code node} in
     * {@code context}. Equivalent to
     * {@code subject.hasPermission(node, context)}.
     */
    public static boolean check(PermissionSubject subject, String node, String context) {
        Objects.requireNonNull(subject, "subject");
        return subject.hasPermission(node, context);
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

    /**
     * Throws {@link PermissionDeniedException} if {@code subject} does not
     * have {@code node} in {@code context}; otherwise returns normally.
     * The exception reports the context as well as the node.
     *
     * @throws PermissionDeniedException if {@code subject} lacks
     *         {@code node} in {@code context}
     */
    public static void require(PermissionSubject subject, String node, String context) {
        Objects.requireNonNull(subject, "subject");
        if (!subject.hasPermission(node, context)) {
            throw new PermissionDeniedException(node, context, subject);
        }
    }
}
