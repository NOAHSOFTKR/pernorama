package pernorama.annotation;

import java.lang.reflect.Method;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves the permission node required to invoke a {@link Method}, based
 * on the {@link Perm} and {@link PermGroup} annotations declared on it.
 * <p>
 * This is the single place that turns annotation metadata into a
 * permission node string; both {@link pernorama.interceptor.PermissionInterceptor}
 * and {@link pernorama.permission.PermissionRegistry} resolve method-level
 * permissions through it, so the resolution rule only exists once.
 *
 * <h2>Resolution rule</h2>
 * Only annotations declared directly on the given {@link Method} object
 * are considered, using plain {@link Method#getAnnotation(Class)}
 * semantics:
 * <ul>
 *   <li>A method with no {@link Perm} requires no permission.</li>
 *   <li>A method with {@link Perm} combines it with the {@link PermGroup}
 *       declared on {@link Method#getDeclaringClass()}, if any, joined
 *       with {@code "."}.</li>
 *   <li>A method inherited without being overridden (including an
 *       un-overridden interface default method) reports its declaring
 *       class as the class that originally declared it, so its
 *       {@link Perm}/{@link PermGroup} are found naturally.</li>
 *   <li><b>An overriding method does not inherit the {@link Perm} of the
 *       method it overrides.</b> This matches plain Java annotation
 *       semantics (method-level annotations are never inherited across
 *       overrides) and avoids a permission requirement "reappearing"
 *       from a hierarchy walk that the overriding class cannot see by
 *       reading its own source. If an override should still require a
 *       permission, redeclare {@link Perm} on it explicitly.</li>
 * </ul>
 *
 * <h2>Caching</h2>
 * Resolution results are cached per {@link Method}, since this sits on
 * the hot path of every {@link pernorama.interceptor.PermissionInterceptor}
 * invocation. The cache is unbounded and lives for the lifetime of the
 * JVM, keyed by {@link Method} identity (which pins its declaring
 * {@link Class}). This is safe for a normal, fixed set of application
 * classes, but it is <b>not</b> a good fit for classes generated at
 * runtime and then discarded — a CGLIB/dynamic-proxy-heavy framework
 * integration or a hot class-reloading setup would leak a {@code Method}
 * (and its {@code Class}/{@code ClassLoader}) into this cache forever
 * for every regenerated class. Framework integrations that proxy
 * annotated methods are out of scope for this Beta (see the README);
 * revisit this cache before shipping one.
 */
public final class PermissionAnnotationResolver {

    private static final ConcurrentHashMap<Method, Optional<String>> CACHE = new ConcurrentHashMap<>();

    private PermissionAnnotationResolver() {
    }

    /**
     * Returns the permission node required to invoke {@code method}, or
     * {@link Optional#empty()} if it declares no {@link Perm}.
     */
    public static Optional<String> resolve(Method method) {
        Objects.requireNonNull(method, "method");
        return CACHE.computeIfAbsent(method, PermissionAnnotationResolver::doResolve);
    }

    /**
     * Joins a {@link PermGroup} value with a {@link Perm} value, e.g.
     * {@code ("users", "create")} becomes {@code "users.create"}. A
     * {@code null} or blank {@code groupPrefix} leaves {@code value}
     * unchanged.
     */
    public static String combine(String groupPrefix, String value) {
        Objects.requireNonNull(value, "value");
        if (groupPrefix == null || groupPrefix.isBlank()) {
            return value;
        }
        return groupPrefix + "." + value;
    }

    private static Optional<String> doResolve(Method method) {
        Perm perm = method.getAnnotation(Perm.class);
        if (perm == null) {
            return Optional.empty();
        }
        PermGroup group = method.getDeclaringClass().getAnnotation(PermGroup.class);
        String groupPrefix = group != null ? group.value() : null;
        return Optional.of(combine(groupPrefix, perm.value()));
    }
}
