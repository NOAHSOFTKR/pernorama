package pernorama.role;

import org.junit.jupiter.api.Test;
import pernorama.permission.ContextPolicy;
import pernorama.permission.PermissionExplanation;
import pernorama.permission.PermissionExplanation.Contribution;
import pernorama.permission.PermissionExplanation.Layer;
import pernorama.permission.PermissionExplanation.Provenance;
import pernorama.permission.PermissionResolver.Decision;
import pernorama.subject.MemoryPermissionSubject;
import pernorama.subject.PermissionSubject;

import java.util.List;
import java.util.Optional;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RoleExplanationTest {

    private static Role role(String id, String... rules) {
        Role.Builder builder = Role.builder(id);
        for (String rule : rules) {
            builder.permission(rule);
        }
        return builder.build();
    }

    private static List<Object> decisiveSources(PermissionExplanation explanation) {
        return explanation.contributions().stream().filter(Contribution::decisive).map(Contribution::source).toList();
    }

    @Test
    void allowOverridesReportsThePermittingRoleNotTheDeny() {
        Role editor = role("editor", "users.*");
        Role suspended = role("suspended", "-users.delete");
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("bob", editor);
        assignments.assign("bob", suspended);

        PermissionExplanation explanation = assignments.subject("bob").explain("users.delete");

        assertTrue(explanation.allowed());
        assertEquals(Optional.of("ALLOW_OVERRIDES"), explanation.resolutionPolicy());
        assertEquals(Provenance.COMPLETE, explanation.provenance());
        assertEquals(Optional.of(Layer.EXACT_CONTEXT), explanation.decidingLayer());
        assertEquals(List.of(new RoleAssignment(editor, null)), decisiveSources(explanation));
        // the deny is reported, but not as a veto
        Contribution denying = explanation.contributions().get(1);
        assertEquals(new RoleAssignment(suspended, null), denying.source());
        assertFalse(denying.decisive());
        assertEquals(Optional.of(Decision.DENIED), denying.explanation().decision());
    }

    @Test
    void allowOverridesIsDeniedOnlyWhenNoRolePermits() {
        RoleAssignments<String> assignments = new RoleAssignments<>();
        Role suspended = role("suspended", "-users.delete");
        Role reader = role("reader", "posts.read");
        assignments.assign("bob", suspended);
        assignments.assign("bob", reader);

        PermissionExplanation explanation = assignments.subject("bob").explain("users.delete");

        assertFalse(explanation.allowed());
        assertEquals(Optional.of(Decision.DENIED), explanation.decision());
        assertEquals(List.of(new RoleAssignment(suspended, null)), decisiveSources(explanation));
        assertEquals(Optional.of(Decision.NOT_COVERED), explanation.contributions().get(1).explanation().decision());
    }

    @Test
    void denyOverridesReportsTheVeto() {
        Role editor = role("editor", "users.*");
        Role suspended = role("suspended", "-users.delete");
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("bob", editor);
        assignments.assign("bob", suspended);

        PermissionExplanation explanation =
                assignments.subject("bob", PermissionResolutionPolicy.DENY_OVERRIDES).explain("users.delete");

        assertFalse(explanation.allowed());
        assertEquals(Optional.of(Decision.DENIED), explanation.decision());
        assertEquals(Optional.of("DENY_OVERRIDES"), explanation.resolutionPolicy());
        assertEquals(List.of(new RoleAssignment(suspended, null)), decisiveSources(explanation));
    }

    @Test
    void denyOverridesPermitsWithEveryPermittingRole() {
        RoleAssignments<String> assignments = new RoleAssignments<>();
        Role editor = role("editor", "users.*");
        Role admin = role("admin", "*");
        assignments.assign("bob", editor);
        assignments.assign("bob", admin);

        PermissionExplanation explanation =
                assignments.subject("bob", PermissionResolutionPolicy.DENY_OVERRIDES).explain("users.delete");

        assertTrue(explanation.allowed());
        assertEquals(List.of(new RoleAssignment(editor, null), new RoleAssignment(admin, null)),
                decisiveSources(explanation));
    }

    @Test
    void roleHeldInTheContextDecidesBeforeGlobalRoles() {
        Role teacher = role("teacher", "students.*");
        Role restricted = role("restricted", "-students.*");
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("bob", restricted);
        assignments.assign("bob", teacher, "academy:123");
        PermissionSubject bob = assignments.subject("bob", PermissionResolutionPolicy.DENY_OVERRIDES);

        PermissionExplanation there = bob.explain("students.edit", "academy:123");
        assertTrue(there.allowed());
        assertEquals(Optional.of(ContextPolicy.GLOBAL_FALLBACK), there.contextPolicy());
        assertEquals(Optional.of(Layer.EXACT_CONTEXT), there.decidingLayer());
        assertEquals(List.of(new RoleAssignment(teacher, "academy:123")), decisiveSources(there));
        // the global deny applied but did not decide, even under DENY_OVERRIDES
        assertEquals(2, there.contributions().size());

        PermissionExplanation elsewhere = bob.explain("students.edit", "academy:456");
        assertFalse(elsewhere.allowed());
        assertEquals(Optional.of(Layer.GLOBAL_FALLBACK), elsewhere.decidingLayer());
        assertEquals(List.of(new RoleAssignment(restricted, null)), decisiveSources(elsewhere));
        assertEquals(1, elsewhere.contributions().size());
    }

    @Test
    void exactPolicyLeavesGlobalRolesOut() {
        Role admin = role("admin", "*");
        RoleAssignments<String> assignments =
                new RoleAssignments<>(new MemoryRoleAssignmentStore<>(), ContextPolicy.EXACT);
        assignments.assign("bob", admin);

        PermissionExplanation explanation = assignments.subject("bob").explain("students.edit", "academy:123");

        assertFalse(explanation.allowed());
        assertEquals(Optional.of(Decision.NOT_COVERED), explanation.decision());
        assertEquals(Optional.of(ContextPolicy.EXACT), explanation.contextPolicy());
        assertEquals(List.of(), explanation.contributions());
        assertEquals(Provenance.COMPLETE, explanation.provenance());
    }

    @Test
    void roleExplanationReportsItsOwnRules() {
        Role teacher = role("teacher", "students.*", "-students.delete");
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", teacher, "academy:123");

        PermissionExplanation explanation = assignments.subject("alice").explain("students.delete", "academy:123");
        PermissionExplanation ofRole = explanation.contributions().get(0).explanation();

        // a role's rules carry no context of their own
        assertEquals(Optional.empty(), ofRole.context());
        assertEquals(Optional.of(Decision.DENIED), ofRole.decision());
        assertEquals("-students.delete", ofRole.matches().get(0).grant().rule());
        assertTrue(ofRole.matches().get(0).decisive());
    }

    @Test
    void customPolicyIsReportedWithPartialProvenance() {
        Role editor = role("editor", "users.*");
        PermissionResolutionPolicy firstRoleOnly = (held, node, context) ->
                !held.isEmpty() && held.get(0).role().permissions().hasPermission(node);
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("bob", editor);

        PermissionExplanation explanation = assignments.subject("bob", firstRoleOnly).explain("users.read");

        assertTrue(explanation.allowed());
        assertEquals(Provenance.PARTIAL, explanation.provenance());
        assertEquals(Optional.empty(), explanation.resolutionPolicy());
        assertEquals(Optional.empty(), explanation.decidingLayer());
        assertEquals(List.of(), decisiveSources(explanation));
        assertEquals(1, explanation.contributions().size());

        PermissionExplanation denied = assignments.subject("bob", firstRoleOnly).explain("posts.read");
        assertFalse(denied.allowed());
        assertEquals(Optional.empty(), denied.decision());
    }

    @Test
    void roleBackedBySubjectIsCountedOnlyByWhetherItPermits() {
        PermissionSubject opaque = new PermissionSubject() {
            @Override
            public boolean hasPermission(String node, String context) {
                return node.startsWith("reports.");
            }

            @Override
            public void grant(String node, String context) {
            }

            @Override
            public void revoke(String node, String context) {
            }
        };
        Role auditor = Role.builder("auditor").permissions(opaque).build();
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("carol", auditor);

        PermissionExplanation allowed = assignments.subject("carol").explain("reports.read");
        assertTrue(allowed.allowed());
        assertEquals(Provenance.PARTIAL, allowed.provenance());
        assertEquals(List.of(new RoleAssignment(auditor, null)), decisiveSources(allowed));
        assertEquals(Provenance.UNAVAILABLE, allowed.contributions().get(0).explanation().provenance());

        PermissionExplanation denied = assignments.subject("carol").explain("users.read");
        assertFalse(denied.allowed());
        assertEquals(Optional.of(Decision.NOT_COVERED), denied.decision());
        assertEquals(Provenance.PARTIAL, denied.provenance());
        assertEquals(Optional.empty(), denied.contributions().get(0).explanation().decision());
    }

    @Test
    void explanationAlwaysAgreesWithTheCheck() {
        Role[] roles = {
                role("all", "*"), role("none", "-*"), role("users", "users.*"),
                role("no-delete", "-users.delete"), role("delete-only", "-users.*", "users.delete"),
                Role.builder("backed").permissions(new MemoryPermissionSubject(List.of("users.read", "-users.delete")))
                        .build()
        };
        String[] contexts = {null, "a:1", "a:2"};
        String[] nodes = {"users.read", "users.delete", "posts.read"};
        PermissionResolutionPolicy[] policies =
                {PermissionResolutionPolicy.ALLOW_OVERRIDES, PermissionResolutionPolicy.DENY_OVERRIDES};
        Random random = new Random(15);

        for (ContextPolicy contextPolicy : ContextPolicy.values()) {
            for (int round = 0; round < 200; round++) {
                RoleAssignments<String> assignments =
                        new RoleAssignments<>(new MemoryRoleAssignmentStore<>(), contextPolicy);
                int count = random.nextInt(5);
                for (int i = 0; i < count; i++) {
                    assignments.assign("t", roles[random.nextInt(roles.length)],
                            contexts[random.nextInt(contexts.length)]);
                }
                for (PermissionResolutionPolicy policy : policies) {
                    PermissionSubject subject = assignments.subject("t", policy);
                    for (String node : nodes) {
                        for (String context : contexts) {
                            PermissionExplanation explanation = subject.explain(node, context);
                            assertEquals(subject.hasPermission(node, context), explanation.allowed(),
                                    assignments.assignments("t") + " " + node + " @ " + context);
                            assertTrue(explanation.decision().isPresent());
                        }
                    }
                }
            }
        }
    }
}
