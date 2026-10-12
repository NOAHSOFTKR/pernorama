package pernorama.subject;

import org.junit.jupiter.api.Test;
import pernorama.exception.InvalidPermissionException;
import pernorama.permission.PermissionExplanation;
import pernorama.permission.PermissionResolver;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CompositePermissionSubjectTest {

    @Test
    void permissionFromAnySourceIsEnough() {
        PermissionSubject own = new MemoryPermissionSubject(List.of("profile.edit"));
        PermissionSubject admins = new MemoryPermissionSubject(List.of("users.*"));

        PermissionSubject user = new CompositePermissionSubject(own, admins);

        assertTrue(user.hasPermission("profile.edit"));
        assertTrue(user.hasPermission("users.create"));
        assertFalse(user.hasPermission("posts.delete"));
    }

    @Test
    void collectionAndVarargsConstructorsAgree() {
        PermissionSubject role = new MemoryPermissionSubject(List.of("users.read"));

        assertTrue(new CompositePermissionSubject(role).hasPermission("users.read"));
        assertTrue(new CompositePermissionSubject(List.of(role)).hasPermission("users.read"));
    }

    @Test
    void aCompositeWithNoSourcesPermitsNothing() {
        PermissionSubject user = new CompositePermissionSubject();

        assertFalse(user.hasPermission("users.read"));
    }

    @Test
    void invalidNodeIsRejectedEvenWithNoSourceToAskFirst() {
        PermissionSubject user = new CompositePermissionSubject();

        assertThrows(InvalidPermissionException.class, () -> user.hasPermission("users..read"));
        assertThrows(InvalidPermissionException.class, () -> user.hasPermission("-users.read"));
    }

    @Test
    void aDenyRuleOnlyLimitsTheSourceHoldingIt() {
        PermissionSubject role = new MemoryPermissionSubject(List.of("users.*", "-users.delete"));
        PermissionSubject own = new MemoryPermissionSubject(List.of("users.delete"));

        assertFalse(new CompositePermissionSubject(role).hasPermission("users.delete"));
        assertTrue(new CompositePermissionSubject(role, own).hasPermission("users.delete"));
    }

    @Test
    void grantAndRevokeAreRejected() {
        PermissionSubject role = new MemoryPermissionSubject(List.of("users.read"));
        PermissionSubject user = new CompositePermissionSubject(role);

        assertThrows(UnsupportedOperationException.class, () -> user.grant("users.delete"));
        assertThrows(UnsupportedOperationException.class, () -> user.revoke("users.read"));
    }

    @Test
    void sourcesViewIsUnmodifiableAndKeepsItsOrder() {
        PermissionSubject first = new MemoryPermissionSubject();
        PermissionSubject second = new MemoryPermissionSubject();

        CompositePermissionSubject user = new CompositePermissionSubject(first, second);

        assertEquals(List.of(first, second), user.sources());
        assertThrows(UnsupportedOperationException.class, () -> user.sources().add(new MemoryPermissionSubject()));
    }

    @Test
    void changesToASourceAreVisibleThroughTheComposite() {
        MemoryPermissionSubject role = new MemoryPermissionSubject();
        PermissionSubject user = new CompositePermissionSubject(role);

        assertFalse(user.hasPermission("users.read"));

        role.grant("users.read");

        assertTrue(user.hasPermission("users.read"));
    }

    @Test
    void rejectsNullSources() {
        assertThrows(NullPointerException.class, () -> new CompositePermissionSubject((PermissionSubject) null));
        assertThrows(NullPointerException.class, () -> new CompositePermissionSubject((PermissionSubject[]) null));

        List<PermissionSubject> withNullElement = new ArrayList<>();
        withNullElement.add(null);

        assertThrows(NullPointerException.class, () -> new CompositePermissionSubject(withNullElement));
    }

    @Test
    void theContextIsPassedToEverySource() {
        MemoryPermissionSubject own = new MemoryPermissionSubject();
        MemoryPermissionSubject teachers = new MemoryPermissionSubject();
        own.grant("profile.edit");
        teachers.grant("students.edit", "academy:123");

        PermissionSubject user = new CompositePermissionSubject(own, teachers);

        assertTrue(user.hasPermission("students.edit", "academy:123"));
        assertFalse(user.hasPermission("students.edit", "academy:456"));
        assertTrue(user.hasPermission("profile.edit", "academy:123")); // GLOBAL_FALLBACK in the source
        assertThrows(IllegalArgumentException.class, () -> user.hasPermission("profile.edit", ""));
        assertThrows(UnsupportedOperationException.class, () -> user.grant("profile.edit", "academy:123"));
        assertThrows(UnsupportedOperationException.class, () -> user.revoke("profile.edit", "academy:123"));
    }

    // --- explain ---------------------------------------------------------

    private static PermissionSubject opaque(boolean answer) {
        return new PermissionSubject() {
            @Override
            public boolean hasPermission(String node, String context) {
                return answer;
            }

            @Override
            public void grant(String node, String context) {
            }

            @Override
            public void revoke(String node, String context) {
            }
        };
    }

    @Test
    void explainMarksEveryPermittingSourceDecisive() {
        PermissionSubject own = new MemoryPermissionSubject(List.of("-users.delete"));
        PermissionSubject admins = new MemoryPermissionSubject(List.of("users.*"));
        PermissionSubject owners = new MemoryPermissionSubject(List.of("*"));

        PermissionExplanation explanation =
                new CompositePermissionSubject(own, admins, owners).explain("users.delete");

        assertTrue(explanation.allowed());
        assertEquals(Optional.of("ANY_SOURCE"), explanation.resolutionPolicy());
        assertEquals(PermissionExplanation.Provenance.COMPLETE, explanation.provenance());
        assertEquals(List.of(own, admins, owners),
                explanation.contributions().stream().map(PermissionExplanation.Contribution::source).toList());
        assertEquals(List.of(false, true, true),
                explanation.contributions().stream().map(PermissionExplanation.Contribution::decisive).toList());
    }

    @Test
    void explainTellsDeniedFromNotCovered() {
        PermissionSubject own = new MemoryPermissionSubject(List.of("-users.delete"));
        PermissionSubject readers = new MemoryPermissionSubject(List.of("posts.read"));
        PermissionSubject user = new CompositePermissionSubject(own, readers);

        PermissionExplanation denied = user.explain("users.delete");
        assertFalse(denied.allowed());
        assertEquals(Optional.of(PermissionResolver.Decision.DENIED), denied.decision());
        assertEquals(List.of(true, false),
                denied.contributions().stream().map(PermissionExplanation.Contribution::decisive).toList());

        PermissionExplanation uncovered = user.explain("billing.view");
        assertEquals(Optional.of(PermissionResolver.Decision.NOT_COVERED), uncovered.decision());
        assertEquals(PermissionExplanation.Provenance.COMPLETE, uncovered.provenance());
        assertTrue(uncovered.contributions().stream().noneMatch(PermissionExplanation.Contribution::decisive));

        PermissionExplanation empty = new CompositePermissionSubject().explain("users.read");
        assertEquals(Optional.of(PermissionResolver.Decision.NOT_COVERED), empty.decision());
    }

    @Test
    void explainDoesNotInventADecisionForAnOpaqueSource() {
        PermissionSubject own = new MemoryPermissionSubject(List.of("posts.read"));
        PermissionSubject user = new CompositePermissionSubject(own, opaque(false));

        PermissionExplanation explanation = user.explain("users.read");

        assertFalse(explanation.allowed());
        assertEquals(Optional.empty(), explanation.decision());
        assertEquals(PermissionExplanation.Provenance.PARTIAL, explanation.provenance());

        PermissionExplanation allOpaque = new CompositePermissionSubject(opaque(false)).explain("users.read");
        assertEquals(PermissionExplanation.Provenance.UNAVAILABLE, allOpaque.provenance());

        PermissionExplanation permitted = new CompositePermissionSubject(own, opaque(true)).explain("users.read");
        assertTrue(permitted.allowed());
        assertEquals(PermissionExplanation.Provenance.PARTIAL, permitted.provenance());
    }

    @Test
    void explainValidatesBeforeAskingSources() {
        PermissionSubject user = new CompositePermissionSubject(opaque(true));

        assertThrows(InvalidPermissionException.class, () -> user.explain("users.*"));
        assertThrows(IllegalArgumentException.class, () -> user.explain("users.read", ""));
    }

    private static PermissionSubject throwing() {
        return new PermissionSubject() {
            @Override
            public boolean hasPermission(String node, String context) {
                throw new IllegalStateException("source unavailable");
            }

            @Override
            public void grant(String node, String context) {
            }

            @Override
            public void revoke(String node, String context) {
            }
        };
    }

    @Test
    void explainSurvivesASourceTheCheckNeverReaches() {
        PermissionSubject permitting = new MemoryPermissionSubject(List.of("a.*"));
        PermissionSubject user = new CompositePermissionSubject(permitting, throwing());

        assertTrue(user.hasPermission("a.b"));
        PermissionExplanation explanation = user.explain("a.b");

        assertTrue(explanation.allowed());
        assertEquals(PermissionExplanation.Provenance.PARTIAL, explanation.provenance());
        assertEquals(List.of(permitting),
                explanation.contributions().stream().map(PermissionExplanation.Contribution::source).toList());
    }

    @Test
    void explainPropagatesAFailureTheCheckWouldHit() {
        PermissionSubject user = new CompositePermissionSubject(
                new MemoryPermissionSubject(List.of("posts.read")), throwing(), opaque(true));

        assertThrows(IllegalStateException.class, () -> user.hasPermission("a.b"));
        assertThrows(IllegalStateException.class, () -> user.explain("a.b"));
    }

    @Test
    void explainAsksEachSourceOnce() {
        AtomicInteger calls = new AtomicInteger();
        PermissionSubject counted = new PermissionSubject() {
            @Override
            public boolean hasPermission(String node, String context) {
                calls.incrementAndGet();
                return false;
            }

            @Override
            public void grant(String node, String context) {
            }

            @Override
            public void revoke(String node, String context) {
            }
        };

        new CompositePermissionSubject(counted).explain("a.b");

        assertEquals(1, calls.get());
    }
}
