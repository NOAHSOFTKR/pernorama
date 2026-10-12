package pernorama.permission;

import org.junit.jupiter.api.Test;
import pernorama.exception.InvalidPermissionException;
import pernorama.permission.PermissionExplanation.Layer;
import pernorama.permission.PermissionExplanation.Provenance;
import pernorama.permission.PermissionExplanation.RuleMatch;
import pernorama.permission.PermissionResolver.Decision;
import pernorama.subject.MemoryPermissionSubject;
import pernorama.subject.PermissionSubject;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionExplanationTest {

    private static RuleMatch match(String rule, boolean decisive) {
        return new RuleMatch(new PermissionGrant(rule, null), decisive);
    }

    private static RuleMatch match(String rule, String context, boolean decisive) {
        return new RuleMatch(new PermissionGrant(rule, context), decisive);
    }

    // --- rule precedence (PermissionResolver.explain) -----------------------

    @Test
    void exactRuleBeatsWildcard() {
        PermissionExplanation explanation =
                PermissionResolver.explain(List.of("users.*", "-users.delete"), "users.delete");

        assertFalse(explanation.allowed());
        assertEquals(Optional.of(Decision.DENIED), explanation.decision());
        assertEquals(Provenance.COMPLETE, explanation.provenance());
        assertEquals(List.of(match("-users.delete", true), match("users.*", false)), explanation.matches());
        assertTrue(explanation.matches().get(0).deny());
        assertFalse(explanation.matches().get(0).wildcard());
        assertTrue(explanation.matches().get(1).wildcard());
    }

    @Test
    void moreSpecificWildcardWins() {
        PermissionExplanation explanation =
                PermissionResolver.explain(List.of("*", "-users.*", "users.profile.*"), "users.profile.edit");

        assertTrue(explanation.allowed());
        assertEquals(Optional.of(Decision.PERMITTED), explanation.decision());
        assertEquals(List.of(match("users.profile.*", true), match("-users.*", false), match("*", false)),
                explanation.matches());
    }

    @Test
    void denyWinsATieAndBothRulesAreReported() {
        PermissionExplanation explanation =
                PermissionResolver.explain(List.of("users.*", "-users.*"), "users.read");

        assertEquals(Optional.of(Decision.DENIED), explanation.decision());
        assertEquals(List.of(match("-users.*", true), match("users.*", false)), explanation.matches());
    }

    @Test
    void uncoveredNodeHasNoMatches() {
        PermissionExplanation explanation =
                PermissionResolver.explain(List.of("users.*", "posts.read"), "billing.view");

        assertFalse(explanation.allowed());
        assertEquals(Optional.of(Decision.NOT_COVERED), explanation.decision());
        assertEquals(Provenance.COMPLETE, explanation.provenance());
        assertEquals(List.of(), explanation.matches());
        assertEquals(Optional.empty(), explanation.decidingLayer());
        assertEquals(Optional.empty(), explanation.contextPolicy());
    }

    @Test
    void ruleThatDoesNotCoverTheNodeIsLeftOut() {
        PermissionExplanation explanation =
                PermissionResolver.explain(List.of("users.*", "-users.delete"), "users.delete.hard");

        assertTrue(explanation.allowed());
        assertEquals(List.of(match("users.*", true)), explanation.matches());
    }

    @Test
    void explainValidatesLikeDecide() {
        assertThrows(InvalidPermissionException.class, () -> PermissionResolver.explain(List.of("users.*"), "-users"));
        assertThrows(InvalidPermissionException.class,
                () -> PermissionResolver.explain(List.of("users.*.read"), "users.read"));
    }

    // --- contexts --------------------------------------------------------

    @Test
    void contextLayerOverridesGlobalUnderFallback() {
        MemoryPermissionSubject teacher = new MemoryPermissionSubject(ContextPolicy.GLOBAL_FALLBACK);
        teacher.grant("students.delete");
        teacher.grant("-students.*", "academy:123");

        PermissionExplanation explanation = teacher.explain("students.delete", "academy:123");

        assertFalse(explanation.allowed());
        assertEquals(Optional.of("academy:123"), explanation.context());
        assertEquals(Optional.of(Decision.DENIED), explanation.decision());
        assertEquals(Optional.of(ContextPolicy.GLOBAL_FALLBACK), explanation.contextPolicy());
        assertEquals(Optional.of(Layer.EXACT_CONTEXT), explanation.decidingLayer());
        // the global rule is more specific but is reported as overridden
        assertEquals(List.of(match("-students.*", "academy:123", true), match("students.delete", false)),
                explanation.matches());
    }

    @Test
    void globalLayerDecidesWhenContextSaysNothing() {
        MemoryPermissionSubject teacher = new MemoryPermissionSubject(ContextPolicy.GLOBAL_FALLBACK);
        teacher.grant("students.delete");
        teacher.grant("-students.*", "academy:123");
        teacher.grant("posts.read", "academy:456");

        PermissionExplanation explanation = teacher.explain("students.delete", "academy:456");

        assertTrue(explanation.allowed());
        assertEquals(Optional.of(Layer.GLOBAL_FALLBACK), explanation.decidingLayer());
        assertEquals(List.of(match("students.delete", true)), explanation.matches());
    }

    @Test
    void contextLayerCanReAllowWhatGlobalDenies() {
        MemoryPermissionSubject user = new MemoryPermissionSubject(ContextPolicy.GLOBAL_FALLBACK);
        user.grant("-students.delete");
        user.grant("students.*", "academy:123");

        PermissionExplanation explanation = user.explain("students.delete", "academy:123");

        assertTrue(explanation.allowed());
        assertEquals(Optional.of(Layer.EXACT_CONTEXT), explanation.decidingLayer());
        assertEquals(List.of(match("students.*", "academy:123", true), match("-students.delete", false)),
                explanation.matches());
    }

    @Test
    void exactPolicyNeverFallsBack() {
        MemoryPermissionSubject user = new MemoryPermissionSubject(ContextPolicy.EXACT);
        user.grant("students.read");

        PermissionExplanation explanation = user.explain("students.read", "academy:123");

        assertFalse(explanation.allowed());
        assertEquals(Optional.of(Decision.NOT_COVERED), explanation.decision());
        assertEquals(Optional.of(ContextPolicy.EXACT), explanation.contextPolicy());
        assertEquals(Optional.empty(), explanation.decidingLayer());
        assertEquals(List.of(), explanation.matches());
    }

    @Test
    void checkWithoutContextUsesOnlyGrantsWithoutContext() {
        MemoryPermissionSubject user = new MemoryPermissionSubject(ContextPolicy.GLOBAL_FALLBACK);
        user.grant("students.*");
        user.grant("-students.delete", "academy:123");

        PermissionExplanation explanation = user.explain("students.delete");

        assertTrue(explanation.allowed());
        assertEquals(Optional.empty(), explanation.context());
        assertEquals(Optional.of(Layer.EXACT_CONTEXT), explanation.decidingLayer());
        assertEquals(List.of(match("students.*", true)), explanation.matches());
    }

    @Test
    void grantsInOtherContextsAreLeftOut() {
        PermissionExplanation explanation = ContextPolicy.GLOBAL_FALLBACK.explain(
                List.of(new PermissionGrant("students.*", "academy:456")), "students.read", "academy:123");

        assertEquals(Optional.of(Decision.NOT_COVERED), explanation.decision());
        assertEquals(List.of(), explanation.matches());
    }

    @Test
    void explainValidatesLikePermits() {
        assertThrows(InvalidPermissionException.class,
                () -> ContextPolicy.EXACT.explain(List.of(), "users.*", null));
        assertThrows(IllegalArgumentException.class,
                () -> ContextPolicy.EXACT.explain(List.of(), "users.read", ""));
        assertThrows(NullPointerException.class,
                () -> ContextPolicy.EXACT.explain(null, "users.read", null));
    }

    /**
     * The explanation runs the same evaluation as the check, so it must give
     * the same answer for any rule set, under either policy, in or out of a
     * context.
     */
    @Test
    void explanationAlwaysAgreesWithTheCheck() {
        String[] rules = {"*", "-*", "users.*", "-users.*", "users.delete", "-users.delete",
                "users.delete.*", "-users.delete.*", "posts.read", "-posts.*"};
        String[] contexts = {null, "a:1", "a:2"};
        String[] nodes = {"users", "users.read", "users.delete", "users.delete.hard", "posts.read", "billing"};
        Random random = new Random(15);

        for (ContextPolicy policy : ContextPolicy.values()) {
            for (int round = 0; round < 300; round++) {
                MemoryPermissionSubject subject = new MemoryPermissionSubject(policy);
                List<String> plainRules = new ArrayList<>();
                int count = random.nextInt(6);
                for (int i = 0; i < count; i++) {
                    String rule = rules[random.nextInt(rules.length)];
                    String context = contexts[random.nextInt(contexts.length)];
                    subject.grant(rule, context);
                    if (context == null) {
                        plainRules.add(rule);
                    }
                }
                for (String node : nodes) {
                    for (String context : contexts) {
                        PermissionExplanation explanation = subject.explain(node, context);
                        assertEquals(subject.hasPermission(node, context), explanation.allowed(),
                                subject.grants() + " " + node + " @ " + context);
                        assertEquals(Provenance.COMPLETE, explanation.provenance());
                        assertTrue(explanation.decision().isPresent());
                        long decisive = explanation.matches().stream().filter(RuleMatch::decisive).count();
                        assertEquals(explanation.decision().get() == Decision.NOT_COVERED ? 0 : 1, decisive);
                    }
                    assertEquals(PermissionResolver.decide(plainRules, node),
                            PermissionResolver.explain(plainRules, node).decision().orElseThrow());
                }
            }
        }
    }

    // --- custom subjects and the builder ---------------------------------

    @Test
    void customSubjectReportsOnlyItsAnswer() {
        PermissionSubject apiKey = new PermissionSubject() {
            @Override
            public boolean hasPermission(String node, String context) {
                return node.equals("reports.read");
            }

            @Override
            public void grant(String node, String context) {
            }

            @Override
            public void revoke(String node, String context) {
            }
        };

        PermissionExplanation denied = apiKey.explain("reports.delete");
        assertFalse(denied.allowed());
        assertEquals(Optional.empty(), denied.decision());
        assertEquals(Provenance.UNAVAILABLE, denied.provenance());
        assertEquals(List.of(), denied.matches());

        PermissionExplanation allowed = apiKey.explain("reports.read", "tenant:1");
        assertTrue(allowed.allowed());
        assertEquals(Optional.of(Decision.PERMITTED), allowed.decision());
        assertEquals(Provenance.UNAVAILABLE, allowed.provenance());
        assertEquals(Optional.of("tenant:1"), allowed.context());
    }

    @Test
    void builderRejectsContradictions() {
        assertThrows(IllegalArgumentException.class,
                () -> PermissionExplanation.builder("users.read", null, true).decision(Decision.DENIED));
        assertThrows(IllegalArgumentException.class,
                () -> PermissionExplanation.builder("users.read", null, false).decision(Decision.PERMITTED));
        assertThrows(IllegalStateException.class,
                () -> PermissionExplanation.builder("users.read", null, false).provenance(Provenance.COMPLETE).build());
        assertThrows(InvalidPermissionException.class, () -> PermissionExplanation.unavailable("users.*", null, false));
        assertThrows(IllegalArgumentException.class, () -> PermissionExplanation.unavailable("users.read", "", false));
    }

    // --- subclasses that change the answer -------------------------------

    /** Overrides hasPermission, so its grants no longer explain the answer. */
    static class SuperUser extends MemoryPermissionSubject {
        @Override
        public boolean hasPermission(String node, String context) {
            return true;
        }
    }

    /** Overrides hasPermission without changing it, and explain to say so. */
    static class AuditedUser extends MemoryPermissionSubject {
        @Override
        public boolean hasPermission(String node, String context) {
            return super.hasPermission(node, context);
        }

        @Override
        public PermissionExplanation explain(String node, String context) {
            return contextPolicy().explain(grants(), node, context);
        }
    }

    static class SubclassOfSuperUser extends SuperUser {
    }

    @Test
    void subclassOverridingTheCheckGetsAnAnswerOnlyExplanation() {
        for (MemoryPermissionSubject user : List.of(new SuperUser(), new SubclassOfSuperUser())) {
            user.grant("-a.b");

            PermissionExplanation explanation = user.explain("a.b");

            assertTrue(explanation.allowed());
            assertEquals(Provenance.UNAVAILABLE, explanation.provenance());
            assertEquals(List.of(), explanation.matches());
        }
    }

    @Test
    void subclassCanStillReportItsGrants() {
        AuditedUser user = new AuditedUser();
        user.grant("a.*");

        PermissionExplanation explanation = user.explain("a.b");

        assertTrue(explanation.allowed());
        assertEquals(Provenance.COMPLETE, explanation.provenance());
        assertEquals(List.of(match("a.*", true)), explanation.matches());
    }

    @Test
    void anExplanationThatDisagreesWithItsSubjectIsNotUsed() {
        PermissionSubject inconsistent = new PermissionSubject() {
            @Override
            public boolean hasPermission(String node, String context) {
                return true;
            }

            @Override
            public PermissionExplanation explain(String node, String context) {
                return PermissionExplanation.builder(node, context, false)
                        .decision(Decision.DENIED).provenance(Provenance.COMPLETE).build();
            }

            @Override
            public void grant(String node, String context) {
            }

            @Override
            public void revoke(String node, String context) {
            }
        };

        PermissionSubject composite = new pernorama.subject.CompositePermissionSubject(inconsistent);
        PermissionExplanation explanation = composite.explain("a.b");

        assertTrue(composite.hasPermission("a.b"));
        assertTrue(explanation.allowed());
        assertEquals(Provenance.UNAVAILABLE, explanation.contributions().get(0).explanation().provenance());
    }
}
