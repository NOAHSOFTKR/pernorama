package pernorama.annotation;

import org.junit.jupiter.api.Test;
import pernorama.fixture.BaseDocumentService;
import pernorama.fixture.RedeclaringDocumentService;
import pernorama.fixture.UserService;

import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.lang.reflect.Method;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Pins the memory behavior of {@link PermissionAnnotationResolver}'s
 * cache: a class that the application discards must not stay reachable
 * through it. This is what makes the resolver safe for a proxy-based
 * integration, which resolves against classes generated per target and
 * then thrown away.
 */
class PermissionAnnotationResolverCacheTest {

    private static final String FIXTURE = UserService.class.getName();

    @Test
    void discardedClassIsNotRetainedByTheCache() throws Exception {
        ReferenceQueue<Class<?>> collected = new ReferenceQueue<>();
        WeakReference<Class<?>> generated = resolveAgainstAThrowawayClass(collected);

        assertCollected(generated, collected);
    }

    /**
     * The cache is keyed by declaring class first, so two classes that
     * declare the same signature must not read each other's entry.
     * <p>
     * The two fixtures here require <b>different</b> permissions, which is
     * what makes the assertion discriminating: a cache that confused the
     * two classes and reused one entry would return the wrong value for the
     * other. Two loads of the same bytecode would not show that, since both
     * copies carry the same {@code @Perm}.
     */
    @Test
    void sameSignatureInTwoClassesResolvesIndependently() throws Exception {
        Method base = BaseDocumentService.class.getMethod("read");
        Method redeclaring = RedeclaringDocumentService.class.getMethod("read");

        assertNotSame(base.getDeclaringClass(), redeclaring.getDeclaringClass());
        assertEquals(Optional.of("docs.read"), PermissionAnnotationResolver.resolve(base));
        assertEquals(Optional.of("archive.readArchived"), PermissionAnnotationResolver.resolve(redeclaring));

        // Resolve again, now that both are cached, in case the second write
        // displaced the first.
        assertEquals(Optional.of("docs.read"), PermissionAnnotationResolver.resolve(base));
        assertEquals(Optional.of("archive.readArchived"), PermissionAnnotationResolver.resolve(redeclaring));
    }

    /**
     * Resolves a method on a class loaded by a loader of its own, and
     * returns only a weak reference to it. Everything strong — the class,
     * the method, the loader — is a local of this method, so it is all
     * unreachable once this returns.
     */
    private static WeakReference<Class<?>> resolveAgainstAThrowawayClass(
            ReferenceQueue<Class<?>> collected) throws Exception {
        ClassLoader loader = new SingleClassLoader(FIXTURE, bytecodeOf(FIXTURE));
        Class<?> generated = loader.loadClass(FIXTURE);
        Method method = generated.getMethod("createUser");

        assertNotSame(UserService.class, generated);
        assertEquals(Optional.of("users.create"), PermissionAnnotationResolver.resolve(method));

        return new WeakReference<>(generated, collected);
    }

    /**
     * Waits for the weak reference to be enqueued instead of relying on a
     * fixed sleep after {@link System#gc()}. Explicit GC is still only a
     * request, so the loop gives the VM several opportunities to perform
     * class unloading without making normal CI scheduling part of the
     * assertion.
     */
    private static void assertCollected(
            WeakReference<Class<?>> ref,
            ReferenceQueue<Class<?>> collected) {
        for (int attempt = 0; attempt < 50; attempt++) {
            System.gc();
            try {
                if (collected.remove(100) == ref) {
                    return;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                fail("interrupted while waiting for the class to be collected");
            }
        }

        assertNull(ref.get(), "the resolver cache is still holding the discarded class");
    }

    private static byte[] bytecodeOf(String className) throws IOException {
        String resource = "/" + className.replace('.', '/') + ".class";
        try (InputStream in = PermissionAnnotationResolverCacheTest.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("no bytecode on the classpath for " + className);
            }
            return in.readAllBytes();
        }
    }

    /**
     * Defines one named class itself and delegates everything else to its
     * parent, so the class it defines is a distinct class with the same
     * bytecode — the shape a generated proxy has, without a bytecode
     * library to generate one. Its annotations still resolve to the
     * parent's {@link Perm}.
     */
    private static final class SingleClassLoader extends ClassLoader {

        private final String name;
        private final byte[] bytecode;

        SingleClassLoader(String name, byte[] bytecode) {
            super(SingleClassLoader.class.getClassLoader());
            this.name = name;
            this.bytecode = bytecode;
        }

        @Override
        protected Class<?> loadClass(String requested, boolean resolve) throws ClassNotFoundException {
            if (!name.equals(requested)) {
                return super.loadClass(requested, resolve);
            }
            synchronized (getClassLoadingLock(requested)) {
                Class<?> defined = findLoadedClass(requested);
                if (defined == null) {
                    defined = defineClass(requested, bytecode, 0, bytecode.length);
                }
                if (resolve) {
                    resolveClass(defined);
                }
                return defined;
            }
        }
    }
}
