package pernorama.subject;

import org.junit.jupiter.api.Test;
import pernorama.exception.InvalidPermissionException;
import pernorama.permission.PermissionNode;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MemoryPermissionSubjectTest {

    @Test
    void grantAllowsExactPermission() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();

        subject.grant("users.create");

        assertTrue(subject.hasPermission("users.create"));
        assertFalse(subject.hasPermission("users.delete"));
    }

    @Test
    void hasPermissionAcceptsPermissionNodeToo() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("users.create");

        assertTrue(subject.hasPermission(PermissionNode.of("users.create")));
        assertFalse(subject.hasPermission(PermissionNode.of("users.delete")));
    }

    @Test
    void revokeRemovesAnExactlyGrantedPermission() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("users.create");

        subject.revoke("users.create");

        assertFalse(subject.hasPermission("users.create"));
    }

    @Test
    void revokeOnlyRemovesExactMatchNotWildcardChildren() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("users.*");

        subject.revoke("users.create");

        assertTrue(subject.hasPermission("users.create"));

        subject.revoke("users.*");

        assertFalse(subject.hasPermission("users.create"));
    }

    @Test
    void globalWildcardGrantsEverything() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("*");

        assertTrue(subject.hasPermission("users.create"));
        assertTrue(subject.hasPermission("posts.delete"));
    }

    @Test
    void groupWildcardGrantsOnlyItsOwnGroup() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("users.*");

        assertTrue(subject.hasPermission("users.create"));
        assertTrue(subject.hasPermission("users.delete"));
        assertTrue(subject.hasPermission("users.update"));
        assertFalse(subject.hasPermission("posts.create"));
    }

    @Test
    void constructorAcceptsInitialPermissions() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject(List.of("users.create", "posts.read"));

        assertTrue(subject.hasPermission("users.create"));
        assertTrue(subject.hasPermission("posts.read"));
        assertEquals(Set.of("users.create", "posts.read"), subject.grantedPermissions());
    }

    @Test
    void grantedPermissionsViewIsUnmodifiable() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("users.create");

        assertThrows(UnsupportedOperationException.class, () -> subject.grantedPermissions().add("users.delete"));
    }

    @Test
    void grantRejectsInvalidPattern() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();

        assertThrows(InvalidPermissionException.class, () -> subject.grant("users..create"));
    }

    @Test
    void concurrentGrantsOfDifferentPermissionsAllSucceed() throws InterruptedException {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        int threadCount = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        CountDownLatch ready = new CountDownLatch(threadCount);
        CountDownLatch start = new CountDownLatch(1);

        try {
            for (int i = 0; i < threadCount; i++) {
                int index = i;
                pool.submit(() -> {
                    ready.countDown();
                    await(start);
                    subject.grant("users.perm" + index);
                });
            }
            ready.await();
            start.countDown();
            shutdownAndAwait(pool);
        } finally {
            pool.shutdownNow();
        }

        for (int i = 0; i < threadCount; i++) {
            assertTrue(subject.hasPermission("users.perm" + i));
        }
        assertEquals(threadCount, subject.grantedPermissions().size());
    }

    @Test
    void concurrentGrantAndRevokeOfSamePermissionNeverCorruptsState() throws InterruptedException {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        int iterations = 5_000;
        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch start = new CountDownLatch(1);

        try {
            var granter = pool.submit(() -> {
                await(start);
                for (int i = 0; i < iterations; i++) {
                    subject.grant("users.create");
                }
            });
            var revoker = pool.submit(() -> {
                await(start);
                for (int i = 0; i < iterations; i++) {
                    subject.revoke("users.create");
                }
            });
            start.countDown();
            granter.get();
            revoker.get();
        } catch (Exception e) {
            throw new AssertionError("Concurrent grant/revoke failed", e);
        } finally {
            pool.shutdownNow();
        }

        assertTrue(subject.grantedPermissions().size() <= 1,
                "granted set should never hold more than one entry for a single racing permission");
    }

    @Test
    void hasPermissionDuringConcurrentGrantAndRevokeNeverThrows() throws InterruptedException {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("users.read");
        int readerThreads = 16;
        int iterations = 2_000;
        ExecutorService pool = Executors.newFixedThreadPool(readerThreads + 1);
        CountDownLatch start = new CountDownLatch(1);
        AtomicBoolean stop = new AtomicBoolean(false);
        ConcurrentHashMap<Integer, Boolean> failed = new ConcurrentHashMap<>();

        try {
            for (int i = 0; i < readerThreads; i++) {
                int index = i;
                pool.submit(() -> {
                    await(start);
                    while (!stop.get()) {
                        try {
                            subject.hasPermission("users.read");
                            subject.hasPermission("users.write");
                        } catch (RuntimeException e) {
                            failed.put(index, true);
                        }
                    }
                });
            }
            var writer = pool.submit(() -> {
                await(start);
                for (int i = 0; i < iterations; i++) {
                    subject.grant("users.write");
                    subject.revoke("users.write");
                }
            });
            start.countDown();
            writer.get();
            stop.set(true);
        } catch (Exception e) {
            throw new AssertionError("Concurrent read during grant/revoke failed", e);
        } finally {
            pool.shutdownNow();
        }

        assertTrue(failed.isEmpty(), "hasPermission() threw while racing grant/revoke on another thread");
    }

    @Test
    void manyThreadsRepeatedlyCheckingAPermissionSeeAConsistentGrant() throws InterruptedException {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("users.*");
        int threadCount = 16;
        int checksPerThread = 10_000;
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        ConcurrentHashMap<Integer, Boolean> allPassed = new ConcurrentHashMap<>();

        try {
            for (int i = 0; i < threadCount; i++) {
                int index = i;
                pool.submit(() -> {
                    boolean ok = true;
                    for (int c = 0; c < checksPerThread; c++) {
                        ok &= subject.hasPermission("users.create");
                    }
                    allPassed.put(index, ok);
                });
            }
            shutdownAndAwait(pool);
        } finally {
            pool.shutdownNow();
        }

        for (int i = 0; i < threadCount; i++) {
            assertTrue(allPassed.get(i), "thread " + i + " observed an inconsistent permission check");
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(e);
        }
    }

    private static void shutdownAndAwait(ExecutorService pool) throws InterruptedException {
        pool.shutdown();
        if (!pool.awaitTermination(10, TimeUnit.SECONDS)) {
            throw new AssertionError("Concurrency test did not finish in time");
        }
    }
}
