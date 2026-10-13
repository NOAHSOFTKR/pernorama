package pernorama.conformance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import pernorama.Pernorama;
import pernorama.exception.InvalidPermissionException;
import pernorama.exception.PermissionDeniedException;
import pernorama.permission.ContextPolicy;
import pernorama.permission.Permission;
import pernorama.permission.PermissionExplanation;
import pernorama.permission.PermissionGrant;
import pernorama.permission.PermissionNode;
import pernorama.permission.PermissionResolver;
import pernorama.role.PermissionResolutionPolicy;
import pernorama.role.Role;
import pernorama.role.RoleAssignment;
import pernorama.role.RoleAssignmentDecision;
import pernorama.role.RoleAssignmentPolicy;
import pernorama.role.RoleAssignmentResult;
import pernorama.role.RoleAssignments;
import pernorama.role.RoleGroup;
import pernorama.subject.CompositePermissionSubject;
import pernorama.subject.MemoryPermissionSubject;
import pernorama.subject.PermissionSubject;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.DynamicContainer.dynamicContainer;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

/**
 * Runs the language-neutral fixtures in {@code /spec} against this
 * implementation. The TypeScript suite
 * ({@code typescript/test/conformance.test.ts}) runs the very same files,
 * so an authorization decision — and, where a fixture specifies one, the
 * structure of its explanation — is the same in both languages. The
 * format is described in {@code spec/README.md}.
 * <p>
 * This implementation is the reference: a fixture that disagrees with it
 * is a wrong fixture, not a reason to change the rules here.
 */
class ConformanceTest {

    private static final int SUPPORTED_SPEC_VERSION = 1;
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

    private static final Map<String, RoleAssignmentPolicy> ASSIGNMENT_POLICIES = Map.of(
            "REJECT", RoleAssignmentPolicy.REJECT,
            "REPLACE_EXISTING", RoleAssignmentPolicy.REPLACE_EXISTING,
            "REPLACE_OLDEST", RoleAssignmentPolicy.REPLACE_OLDEST,
            "REPLACE_NEWEST", RoleAssignmentPolicy.REPLACE_NEWEST,
            // custom policies whose decisions break the group's limits
            "BROKEN_REPLACE_NONE", (group, held, requested) -> RoleAssignmentDecision.replace(List.of()),
            "BROKEN_REPLACE_REQUESTED", (group, held, requested) -> RoleAssignmentDecision.replace(List.of(requested)));

    private static final Map<String, PermissionResolutionPolicy> RESOLUTION_POLICIES = Map.of(
            "ALLOW_OVERRIDES", PermissionResolutionPolicy.ALLOW_OVERRIDES,
            "DENY_OVERRIDES", PermissionResolutionPolicy.DENY_OVERRIDES,
            // a custom policy: permitted if any applicable role permits, with no layering
            "CUSTOM_ANY", (assignments, node, context) -> assignments.stream()
                    .anyMatch(assignment -> assignment.role().permissions().hasPermission(node)));

    // ---- permission-cases.json ---------------------------------------------

    @TestFactory
    List<DynamicNode> permissionCases() {
        JsonNode spec = load("permission-cases.json");
        expectKeys("permission-cases", spec,
                "specVersion", "description", "nodes", "rules", "nodeRelations", "ruleMatching", "ruleSets");

        List<DynamicNode> tests = new ArrayList<>();
        tests.add(dynamicTest("nodes", () -> {
            for (JsonNode c : nonEmpty(spec, "nodes")) {
                String value = text(c, "value");
                boolean valid = c.get("valid").asBoolean();
                assertEquals(valid, PermissionNode.isValid(value), "PermissionNode.isValid(" + c.get("value") + ")");
                if (valid) {
                    assertEquals(value, PermissionNode.of(value).name());
                    assertEquals(value, PermissionNode.of(value).toString());
                } else {
                    assertFails("INVALID_PERMISSION", "PermissionNode.of(" + c.get("value") + ")",
                            () -> PermissionNode.of(value));
                }
            }
        }));
        tests.add(dynamicTest("rules", () -> {
            for (JsonNode c : nonEmpty(spec, "rules")) {
                String value = text(c, "value");
                String what = String.valueOf(c.get("value"));
                boolean valid = c.get("valid").asBoolean();
                assertEquals(valid, PermissionResolver.isValidPattern(value), "isValidPattern(" + what + ")");
                MemoryPermissionSubject subject = new MemoryPermissionSubject();
                if (valid) {
                    new PermissionGrant(value, null);
                    subject.grant(value);
                    subject.revoke(value);
                    Role.builder("r").permission(value).build();
                } else {
                    assertFails("INVALID_PERMISSION", "new PermissionGrant(" + what + ")",
                            () -> new PermissionGrant(value, null));
                    assertFails("INVALID_PERMISSION", "grant(" + what + ")", () -> {
                        subject.grant(value);
                        return null;
                    });
                    assertFails("INVALID_PERMISSION", "revoke(" + what + ")", () -> {
                        subject.revoke(value);
                        return null;
                    });
                    assertFails("INVALID_PERMISSION", "Role.permission(" + what + ")",
                            () -> Role.builder("r").permission(value));
                }
            }
        }));
        tests.add(dynamicTest("nodeRelations", () -> {
            for (JsonNode relation : nonEmpty(spec, "nodeRelations")) {
                PermissionNode node = PermissionNode.of(text(relation, "node"));
                assertEquals(strings(relation.get("segments")), node.segments());
                assertEquals(text(relation, "parent"), node.parent().map(PermissionNode::name).orElse(null),
                        "parent of " + node);
                for (JsonNode child : relation.get("childOf")) {
                    String other = text(child, "other");
                    boolean expected = child.get("expected").asBoolean();
                    assertEquals(expected, node.isChildOf(other), node + " isChildOf " + other);
                    assertEquals(expected, node.isChildOf(PermissionNode.of(other)));
                }
            }
        }));
        tests.add(dynamicTest("ruleMatching", () -> {
            for (JsonNode c : nonEmpty(spec, "ruleMatching")) {
                String rule = text(c, "rule");
                String node = text(c, "node");
                String what = c.get("rule") + " vs " + c.get("node");
                if (c.has("error")) {
                    assertFails(text(c, "error"), "matches " + what, () -> PermissionResolver.matches(rule, node));
                    assertFails(text(c, "error"), "denies " + what, () -> PermissionResolver.denies(rule, node));
                } else {
                    assertEquals(c.get("matches").asBoolean(), PermissionResolver.matches(rule, node), "matches " + what);
                    assertEquals(c.get("denies").asBoolean(), PermissionResolver.denies(rule, node), "denies " + what);
                    assertEquals(c.get("matches").asBoolean(), PermissionResolver.matches(rule, PermissionNode.of(node)));
                    assertEquals(c.get("denies").asBoolean(), PermissionResolver.denies(rule, PermissionNode.of(node)));
                }
            }
        }));

        List<DynamicNode> ruleSets = new ArrayList<>();
        for (JsonNode set : nonEmpty(spec, "ruleSets")) {
            String name = text(set, "name");
            ruleSets.add(dynamicTest(name, () -> {
                List<String> rules = strings(set.get("rules"));
                for (JsonNode check : set.get("checks")) {
                    String node = text(check, "node");
                    String what = name + ": " + check.get("node");
                    if (check.has("error")) {
                        String error = text(check, "error");
                        assertFails(error, what + ": decide", () -> PermissionResolver.decide(rules, node));
                        assertFails(error, what + ": matchesAny", () -> PermissionResolver.matchesAny(rules, node));
                        assertFails(error, what + ": explain", () -> PermissionResolver.explain(rules, node));
                        continue;
                    }
                    String decision = text(check, "decision");
                    boolean allowed = decision.equals("PERMITTED");
                    assertEquals(decision, PermissionResolver.decide(rules, node).name(), what + ": decide");
                    assertEquals(allowed, PermissionResolver.matchesAny(rules, node), what + ": matchesAny");
                    assertExplanation(PermissionResolver.explain(rules, node), check, allowed, Map.of(), what);

                    // a role built from the same rules decides the same way
                    Role.Builder builder = Role.builder("r");
                    rules.forEach(builder::permission);
                    Role role = builder.build();
                    assertEquals(allowed, role.permissions().hasPermission(node), what + ": role permits");
                    assertEquals(decision.equals("DENIED"), role.denies(node), what + ": role denies");
                }
            }));
        }
        tests.add(dynamicContainer("ruleSets", ruleSets));
        return tests;
    }

    // ---- context-cases.json ------------------------------------------------

    @TestFactory
    List<DynamicNode> contextCases() {
        JsonNode spec = load("context-cases.json");
        expectKeys("context-cases", spec, "specVersion", "description", "contexts", "applies", "grants", "subjects");

        List<DynamicNode> tests = new ArrayList<>();
        tests.add(dynamicTest("contexts", () -> {
            for (JsonNode c : nonEmpty(spec, "contexts")) {
                String value = text(c, "value");
                String what = String.valueOf(c.get("value"));
                boolean valid = c.get("valid").asBoolean();
                assertEquals(valid, PermissionGrant.isValidContext(value), "isValidContext(" + what + ")");
                if (valid) {
                    assertEquals(value, PermissionGrant.requireValidContext(value));
                    assertEquals(value, new PermissionGrant("a.b", value).context());
                    assertEquals(value != null, new PermissionGrant("a.b", value).hasContext());
                } else {
                    assertFails("ILLEGAL_ARGUMENT", "requireValidContext(" + what + ")",
                            () -> PermissionGrant.requireValidContext(value));
                }
            }
        }));
        tests.add(dynamicTest("applies", () -> {
            for (JsonNode c : nonEmpty(spec, "applies")) {
                ContextPolicy policy = ContextPolicy.valueOf(text(c, "policy"));
                String granted = text(c, "granted");
                String requested = text(c, "requested");
                String what = policy + ".applies(" + c.get("granted") + ", " + c.get("requested") + ")";
                if (c.has("error")) {
                    assertFails(text(c, "error"), what, () -> policy.applies(granted, requested));
                } else {
                    assertEquals(c.get("applies").asBoolean(), policy.applies(granted, requested), what);
                }
            }
        }));
        tests.add(dynamicTest("grants", () -> {
            for (JsonNode c : nonEmpty(spec, "grants")) {
                String rule = text(c, "rule");
                String context = text(c, "context");
                String what = "PermissionGrant(" + c.get("rule") + ", " + c.get("context") + ")";
                if (c.has("error")) {
                    String error = text(c, "error");
                    assertFails(error, what, () -> new PermissionGrant(rule, context));
                    assertFails(error, "grant " + what, () -> {
                        new MemoryPermissionSubject().grant(rule, context);
                        return null;
                    });
                    assertFails(error, "revoke " + what, () -> {
                        new MemoryPermissionSubject().revoke(rule, context);
                        return null;
                    });
                } else {
                    PermissionGrant grant = new PermissionGrant(rule, context);
                    assertEquals(rule, grant.rule());
                    assertEquals(context, grant.context());
                    assertEquals(text(c, "text"), grant.toString(), what);
                }
            }
        }));

        List<DynamicNode> subjects = new ArrayList<>();
        for (JsonNode c : nonEmpty(spec, "subjects")) {
            String name = text(c, "name");
            subjects.add(dynamicTest(name, () -> {
                expectKeys(name, c, "name", "policy", "grants", "revoke", "checks");
                ContextPolicy policy = ContextPolicy.valueOf(text(c, "policy"));
                MemoryPermissionSubject subject = Pernorama.builder().contextPolicy(policy).build().newSubject();
                for (JsonNode grant : c.get("grants")) {
                    subject.grant(ruleOf(grant), contextOf(grant));
                }
                if (c.has("revoke")) {
                    for (JsonNode grant : c.get("revoke")) {
                        subject.revoke(ruleOf(grant), contextOf(grant));
                    }
                }
                assertSame(policy, subject.contextPolicy());

                for (JsonNode check : c.get("checks")) {
                    String node = text(check, "node");
                    String context = text(check, "context");
                    String what = name + ": " + check.get("node") + " @ " + check.get("context");
                    assertCheck(subject, check, Map.of(), what);

                    // the policy over the same grants is the same evaluation
                    Set<PermissionGrant> grants = subject.grants();
                    if (check.has("error")) {
                        String error = text(check, "error");
                        assertFails(error, what + ": permits", () -> policy.permits(grants, node, context));
                        assertFails(error, what + ": policy.explain", () -> policy.explain(grants, node, context));
                    } else {
                        boolean allowed = check.get("allowed").asBoolean();
                        assertEquals(allowed, policy.permits(grants, node, context), what + ": permits");
                        assertExplanation(policy.explain(grants, node, context), check, allowed, Map.of(), what);
                    }
                }
            }));
        }
        tests.add(dynamicContainer("subjects", subjects));
        return tests;
    }

    // ---- role-cases.json ---------------------------------------------------

    @TestFactory
    List<DynamicNode> roleCases() {
        JsonNode spec = load("role-cases.json");
        expectKeys("role-cases", spec, "specVersion", "description", "ids", "groupDefinitions", "composites", "scenarios");

        List<DynamicNode> tests = new ArrayList<>();
        tests.add(dynamicTest("ids", () -> {
            for (JsonNode c : nonEmpty(spec, "ids")) {
                String value = text(c, "value");
                String what = String.valueOf(c.get("value"));
                if (c.get("valid").asBoolean()) {
                    assertEquals(value, Role.builder(value).build().id(), "Role.builder(" + what + ")");
                    assertEquals(value, RoleGroup.builder(value).build().id(), "RoleGroup.builder(" + what + ")");
                } else {
                    assertFails("ILLEGAL_ARGUMENT", "Role.builder(" + what + ")", () -> Role.builder(value));
                    assertFails("ILLEGAL_ARGUMENT", "RoleGroup.builder(" + what + ")", () -> RoleGroup.builder(value));
                }
            }
        }));
        tests.add(dynamicTest("groupDefinitions", () -> {
            for (JsonNode def : nonEmpty(spec, "groupDefinitions")) {
                expectKeys("groupDefinition", def, "min", "max", "policy", "valid", "expectMin", "expectMax");
                String what = def.toString();
                if (def.get("valid").asBoolean()) {
                    RoleGroup group = buildGroup("g", def);
                    if (def.has("expectMin")) {
                        assertEquals(def.get("expectMin").asInt(), group.minAssignments(), what);
                    }
                    if (def.has("expectMax")) {
                        assertEquals(def.get("expectMax").asInt(), group.maxAssignments(), what);
                    }
                } else {
                    assertFails("ILLEGAL_ARGUMENT", what, () -> buildGroup("g", def));
                }
            }
        }));

        List<DynamicNode> composites = new ArrayList<>();
        for (JsonNode c : nonEmpty(spec, "composites")) {
            String name = text(c, "name");
            composites.add(dynamicTest(name, () -> {
                expectKeys(name, c, "name", "sources", "checks");
                Map<Object, String> labels = new IdentityHashMap<>();
                List<PermissionSubject> sources = new ArrayList<>();
                for (JsonNode source : c.get("sources")) {
                    sources.add(buildSubject(source, labels));
                }
                CompositePermissionSubject composite = new CompositePermissionSubject(sources);
                assertEquals(sources.size(), composite.sources().size());
                assertFails("UNSUPPORTED_OPERATION", name + ": grant", () -> {
                    composite.grant("a.b");
                    return null;
                });
                assertFails("UNSUPPORTED_OPERATION", name + ": revoke", () -> {
                    composite.revoke("a.b");
                    return null;
                });
                for (JsonNode check : c.get("checks")) {
                    assertCheck(composite, check, labels, name + ": " + check.get("node") + " @ " + check.get("context"));
                }
            }));
        }
        tests.add(dynamicContainer("composites", composites));

        List<DynamicNode> scenarios = new ArrayList<>();
        for (JsonNode scenario : nonEmpty(spec, "scenarios")) {
            scenarios.add(dynamicTest(text(scenario, "name"), () -> runScenario(scenario)));
        }
        tests.add(dynamicContainer("scenarios", scenarios));
        return tests;
    }

    private static void runScenario(JsonNode scenario) {
        String name = text(scenario, "name");
        expectKeys(name, scenario, "name", "contextPolicy", "groups", "roles", "steps");
        Map<Object, String> labels = new IdentityHashMap<>();

        Map<String, RoleGroup> groups = new HashMap<>();
        if (scenario.has("groups")) {
            for (JsonNode def : scenario.get("groups")) {
                expectKeys("group", def, "key", "id", "min", "max", "policy");
                groups.put(def.has("key") ? text(def, "key") : text(def, "id"), buildGroup(text(def, "id"), def));
            }
        }
        Map<String, Role> roles = new HashMap<>();
        for (JsonNode def : scenario.get("roles")) {
            expectKeys("role", def, "key", "id", "group", "rules", "subject");
            Role.Builder builder = Role.builder(text(def, "id"));
            if (def.has("group")) {
                builder.group(known(groups, text(def, "group"), "group"));
            }
            if (def.has("rules")) {
                strings(def.get("rules")).forEach(builder::permission);
            }
            if (def.has("subject")) {
                builder.permissions(buildSubject(def.get("subject"), labels));
            }
            roles.put(def.has("key") ? text(def, "key") : text(def, "id"), builder.build());
        }

        Pernorama pernorama = Pernorama.builder()
                .contextPolicy(ContextPolicy.valueOf(text(scenario, "contextPolicy")))
                .build();
        RoleAssignments<String> assignments = pernorama.newRoleAssignments();
        assertSame(pernorama.contextPolicy(), assignments.contextPolicy());

        int index = 0;
        for (JsonNode step : scenario.get("steps")) {
            index++;
            String op = text(step, "op");
            String what = name + ": step " + index + " (" + op + ")";
            String target = text(step, "target");
            String context = text(step, "context");
            switch (op) {
                case "assign", "unassign" -> {
                    expectKeys(what, step, "op", "target", "role", "context", "expect", "error");
                    Role role = known(roles, text(step, "role"), "role");
                    Supplier<RoleAssignmentResult> run = () -> op.equals("assign")
                            ? assignments.assign(target, role, context)
                            : assignments.unassign(target, role, context);
                    if (step.has("error")) {
                        List<RoleAssignment> before = assignments.assignments(target);
                        assertFails(text(step, "error"), what, run::get);
                        assertEquals(before, assignments.assignments(target), what + ": nothing may change");
                    } else {
                        assertResult(run.get(), step, role, what);
                    }
                }
                case "roles" -> {
                    expectKeys(what, step, "op", "target", "context", "expect", "error");
                    if (step.has("error")) {
                        assertFails(text(step, "error"), what, () -> assignments.roles(target, context));
                    } else {
                        assertEquals(strings(step.get("expect")), ids(assignments.roles(target, context)), what);
                    }
                }
                case "assignments" -> {
                    expectKeys(what, step, "op", "target", "expect");
                    ArrayNode actual = JSON.arrayNode();
                    for (RoleAssignment assignment : assignments.assignments(target)) {
                        actual.add(JSON.objectNode()
                                .put("role", assignment.role().id())
                                .put("context", assignment.context()));
                    }
                    ArrayNode expected = JSON.arrayNode();
                    for (JsonNode a : step.get("expect")) {
                        expected.add(JSON.objectNode().put("role", text(a, "role")).put("context", text(a, "context")));
                    }
                    assertEquals(expected, actual, what);
                }
                case "check" -> {
                    expectKeys(what, step, "op", "target", "resolution", "node", "context", "allowed", "decision",
                            "explanation", "error");
                    PermissionResolutionPolicy policy = known(RESOLUTION_POLICIES,
                            step.has("resolution") ? text(step, "resolution") : "ALLOW_OVERRIDES", "resolution policy");
                    PermissionSubject subject = assignments.subject(target, policy);
                    assertCheck(subject, step, labels, what);
                    if (!step.has("resolution")) {
                        // the default policy is ALLOW_OVERRIDES
                        assertCheck(assignments.subject(target), step, labels, what + " (default policy)");
                    }
                    assertFails("UNSUPPORTED_OPERATION", what + ": grant", () -> {
                        subject.grant("a.b");
                        return null;
                    });
                    assertFails("UNSUPPORTED_OPERATION", what + ": revoke", () -> {
                        subject.revoke("a.b");
                        return null;
                    });
                }
                case "roleDenies" -> {
                    expectKeys(what, step, "op", "role", "node", "expect", "error");
                    Role role = known(roles, text(step, "role"), "role");
                    String node = text(step, "node");
                    if (step.has("error")) {
                        assertFails(text(step, "error"), what, () -> role.denies(node));
                    } else {
                        assertEquals(step.get("expect").asBoolean(), role.denies(node), what);
                    }
                }
                case "rolePermits" -> {
                    expectKeys(what, step, "op", "role", "node", "context", "expect", "error");
                    Role role = known(roles, text(step, "role"), "role");
                    String node = text(step, "node");
                    if (step.has("error")) {
                        assertFails(text(step, "error"), what, () -> role.permissions().hasPermission(node, context));
                    } else {
                        assertEquals(step.get("expect").asBoolean(), role.permissions().hasPermission(node, context), what);
                    }
                }
                default -> fail(what + ": unknown op");
            }
        }
    }

    private static void assertResult(RoleAssignmentResult result, JsonNode step, Role role, String what) {
        JsonNode expect = step.get("expect");
        expectKeys(what + " expect", expect, "status", "removed", "current", "reason");
        String status = text(expect, "status");
        List<String> removed = strings(expect.get("removed"));
        assertEquals(status, result.status().name(), what + ": status");
        assertEquals(removed, ids(result.removedRoles()), what + ": removed");
        assertEquals(text(expect, "current"), result.currentRole().map(Role::id).orElse(null), what + ": current");
        assertEquals(removed.isEmpty() ? null : removed.get(0), result.previousRole().map(Role::id).orElse(null),
                what + ": previous");
        assertSame(role, result.role(), what + ": role");
        assertEquals(text(step, "context"), result.context().orElse(null), what + ": context");
        assertEquals(role.group(), result.group(), what + ": group");
        assertEquals(status.equals("REJECTED"), result.rejectionReason().isPresent(), what + ": rejection reason presence");
        if (expect.has("reason")) {
            assertEquals(text(expect, "reason"), result.rejectionReason().orElse(null), what + ": reason");
        }
    }

    // ---- checks and explanations -------------------------------------------

    /** Everything a fixture expects of one check against one subject. */
    private static void assertCheck(PermissionSubject subject, JsonNode check, Map<Object, String> labels, String what) {
        String node = text(check, "node");
        String context = text(check, "context");
        if (check.has("error")) {
            String error = text(check, "error");
            assertFails(error, what + ": hasPermission", () -> subject.hasPermission(node, context));
            assertFails(error, what + ": explain", () -> subject.explain(node, context));
            assertFails(error, what + ": Permission.check", () -> Permission.check(subject, node, context));
            assertFails(error, what + ": Permission.require", () -> {
                Permission.require(subject, node, context);
                return null;
            });
            return;
        }
        assertTrue(check.has("allowed") && check.get("allowed").isBoolean(), what + ": fixture needs 'allowed'");
        boolean allowed = check.get("allowed").asBoolean();
        assertEquals(allowed, subject.hasPermission(node, context), what + ": hasPermission");
        assertEquals(allowed, Permission.check(subject, node, context), what + ": Permission.check");
        if (allowed) {
            Permission.require(subject, node, context);
        } else {
            try {
                Permission.require(subject, node, context);
                fail(what + ": Permission.require did not throw");
            } catch (PermissionDeniedException e) {
                assertEquals(node, e.requiredPermission());
                assertEquals(context, e.context().orElse(null));
                assertSame(subject, e.subject());
            }
        }
        assertExplanation(subject.explain(node, context), check, allowed, labels, what);
    }

    private static void assertExplanation(PermissionExplanation actual, JsonNode check, boolean allowed,
                                          Map<Object, String> labels, String what) {
        assertEquals(text(check, "node"), actual.node(), what + ": explanation node");
        assertEquals(text(check, "context"), actual.context().orElse(null), what + ": explanation context");
        assertEquals(allowed, actual.allowed(), what + ": explanation.allowed");
        if (check.has("decision")) {
            assertEquals(text(check, "decision"), actual.decision().map(Enum::name).orElse(null),
                    what + ": explanation.decision");
        }
        if (check.has("explanation")) {
            assertEquals(normalized(check.get("explanation"), what), canonical(actual, labels), what + ": explanation");
            assertEquals(allowed, check.get("explanation").get("allowed").asBoolean(),
                    what + ": fixture explanation contradicts 'allowed'");
        }
    }

    private static ObjectNode canonical(PermissionExplanation explanation, Map<Object, String> labels) {
        ObjectNode json = JSON.objectNode()
                .put("allowed", explanation.allowed())
                .put("decision", explanation.decision().map(Enum::name).orElse(null))
                .put("provenance", explanation.provenance().name())
                .put("contextPolicy", explanation.contextPolicy().map(Enum::name).orElse(null))
                .put("resolutionPolicy", explanation.resolutionPolicy().orElse(null))
                .put("decidingLayer", explanation.decidingLayer().map(Enum::name).orElse(null));
        ArrayNode matches = json.putArray("matches");
        for (PermissionExplanation.RuleMatch match : explanation.matches()) {
            matches.add(JSON.objectNode()
                    .put("rule", match.grant().rule())
                    .put("context", match.grant().context())
                    .put("decisive", match.decisive())
                    .put("deny", match.deny())
                    .put("wildcard", match.wildcard()));
        }
        ArrayNode contributions = json.putArray("contributions");
        for (PermissionExplanation.Contribution contribution : explanation.contributions()) {
            ObjectNode entry = JSON.objectNode();
            entry.set("source", sourceLabel(contribution.source(), labels));
            entry.put("decisive", contribution.decisive());
            entry.set("explanation", canonical(contribution.explanation(), labels));
            contributions.add(entry);
        }
        return json;
    }

    private static ObjectNode sourceLabel(Object source, Map<Object, String> labels) {
        if (source instanceof RoleAssignment assignment) {
            return JSON.objectNode().put("role", assignment.role().id()).put("context", assignment.context());
        }
        String label = labels.get(source);
        assertNotNull(label, "a contribution names a source the fixture did not label");
        return JSON.objectNode().put("subject", label);
    }

    /** An expected explanation with the defaults of spec/README.md filled in. */
    private static ObjectNode normalized(JsonNode expected, String what) {
        expectKeys(what + " explanation", expected, "allowed", "decision", "provenance", "contextPolicy",
                "resolutionPolicy", "decidingLayer", "matches", "contributions");
        for (String required : List.of("allowed", "decision", "provenance")) {
            assertTrue(expected.has(required), what + " explanation: '" + required + "' is required");
        }
        ObjectNode json = JSON.objectNode()
                .put("allowed", expected.get("allowed").asBoolean())
                .put("decision", text(expected, "decision"))
                .put("provenance", text(expected, "provenance"))
                .put("contextPolicy", text(expected, "contextPolicy"))
                .put("resolutionPolicy", text(expected, "resolutionPolicy"))
                .put("decidingLayer", text(expected, "decidingLayer"));
        ArrayNode matches = json.putArray("matches");
        if (expected.has("matches")) {
            for (JsonNode match : expected.get("matches")) {
                expectKeys(what + " match", match, "rule", "context", "decisive", "deny", "wildcard");
                matches.add(JSON.objectNode()
                        .put("rule", text(match, "rule"))
                        .put("context", text(match, "context"))
                        .put("decisive", flag(match, "decisive"))
                        .put("deny", flag(match, "deny"))
                        .put("wildcard", flag(match, "wildcard")));
            }
        }
        ArrayNode contributions = json.putArray("contributions");
        if (expected.has("contributions")) {
            for (JsonNode contribution : expected.get("contributions")) {
                expectKeys(what + " contribution", contribution, "source", "decisive", "explanation");
                JsonNode source = contribution.get("source");
                ObjectNode entry = JSON.objectNode();
                entry.set("source", source.has("role")
                        ? JSON.objectNode().put("role", text(source, "role")).put("context", text(source, "context"))
                        : JSON.objectNode().put("subject", text(source, "subject")));
                entry.put("decisive", flag(contribution, "decisive"));
                entry.set("explanation", normalized(contribution.get("explanation"), what));
                contributions.add(entry);
            }
        }
        return json;
    }

    // ---- building what a fixture describes ---------------------------------

    private static PermissionSubject buildSubject(JsonNode def, Map<Object, String> labels) {
        expectKeys("subject", def, "label", "kind", "policy", "grants", "sources");
        PermissionSubject subject = switch (text(def, "kind")) {
            case "memory" -> memorySubject(def);
            case "opaque" -> {
                // a custom subject that implements only the mandatory methods
                MemoryPermissionSubject memory = memorySubject(def);
                yield new PermissionSubject() {
                    @Override
                    public boolean hasPermission(String node, String context) {
                        return memory.hasPermission(node, context);
                    }

                    @Override
                    public void grant(String node, String context) {
                        memory.grant(node, context);
                    }

                    @Override
                    public void revoke(String node, String context) {
                        memory.revoke(node, context);
                    }
                };
            }
            case "failing" -> new PermissionSubject() {
                @Override
                public boolean hasPermission(String node, String context) {
                    throw new IllegalStateException("this source always fails");
                }

                @Override
                public void grant(String node, String context) {
                    throw new IllegalStateException("this source always fails");
                }

                @Override
                public void revoke(String node, String context) {
                    throw new IllegalStateException("this source always fails");
                }
            };
            case "composite" -> {
                List<PermissionSubject> sources = new ArrayList<>();
                for (JsonNode source : def.get("sources")) {
                    sources.add(buildSubject(source, labels));
                }
                yield new CompositePermissionSubject(sources);
            }
            default -> fail("unknown subject kind '" + text(def, "kind") + "'");
        };
        if (def.has("label")) {
            labels.put(subject, text(def, "label"));
        }
        return subject;
    }

    private static MemoryPermissionSubject memorySubject(JsonNode def) {
        MemoryPermissionSubject memory = new MemoryPermissionSubject(ContextPolicy.valueOf(text(def, "policy")));
        for (JsonNode grant : def.get("grants")) {
            memory.grant(ruleOf(grant), contextOf(grant));
        }
        return memory;
    }

    private static RoleGroup buildGroup(String id, JsonNode def) {
        RoleGroup.Builder builder = RoleGroup.builder(id);
        if (def.has("min")) {
            builder.minAssignments(def.get("min").asInt());
        }
        if (def.has("max")) {
            builder.maxAssignments(def.get("max").asInt());
        }
        if (def.has("policy")) {
            builder.assignmentPolicy(known(ASSIGNMENT_POLICIES, text(def, "policy"), "assignment policy"));
        }
        return builder.build();
    }

    /** A grant is written as a rule string, for no context, or as {@code {"rule", "context"}}. */
    private static String ruleOf(JsonNode grant) {
        return grant.isObject() ? text(grant, "rule") : (grant.isNull() ? null : grant.asText());
    }

    private static String contextOf(JsonNode grant) {
        return grant.isObject() ? text(grant, "context") : null;
    }

    // ---- fixture plumbing --------------------------------------------------

    private static JsonNode load(String name) {
        Path dir = Path.of(System.getProperty("pernorama.spec.dir", "spec"));
        try {
            JsonNode spec = MAPPER.readTree(Files.readString(dir.resolve(name)));
            assertEquals(SUPPORTED_SPEC_VERSION, spec.get("specVersion").asInt(), name + ": unsupported specVersion");
            return spec;
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read conformance fixture " + dir.resolve(name).toAbsolutePath(), e);
        }
    }

    /** Fails on a fixture key this harness does not know, so a new kind of case cannot be silently skipped. */
    private static void expectKeys(String what, JsonNode value, String... allowed) {
        List<String> known = List.of(allowed);
        for (Iterator<String> names = value.fieldNames(); names.hasNext(); ) {
            String key = names.next();
            assertTrue(known.contains(key), what + ": unknown fixture key '" + key + "'");
        }
    }

    private static JsonNode nonEmpty(JsonNode spec, String section) {
        JsonNode cases = spec.get(section);
        assertNotNull(cases, "missing section '" + section + "'");
        assertFalse(cases.isEmpty(), "section '" + section + "' is empty");
        return cases;
    }

    /** The string at {@code key}, or {@code null} if it is absent or JSON null. */
    private static String text(JsonNode node, String key) {
        JsonNode value = node.get(key);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static boolean flag(JsonNode node, String key) {
        return node.has(key) && node.get(key).asBoolean();
    }

    /** The strings in a JSON array, keeping JSON nulls as {@code null}. */
    private static List<String> strings(JsonNode array) {
        List<String> values = new ArrayList<>();
        for (JsonNode value : array) {
            values.add(value.isNull() ? null : value.asText());
        }
        return values;
    }

    private static List<String> ids(List<Role> roles) {
        return roles.stream().map(Role::id).toList();
    }

    private static <T> T known(Map<String, T> table, String name, String what) {
        T found = table.get(name);
        assertNotNull(found, "unknown " + what + " '" + name + "'");
        return found;
    }

    private static String errorKind(Throwable error) {
        if (error instanceof InvalidPermissionException) {
            return "INVALID_PERMISSION";
        }
        if (error instanceof PermissionDeniedException) {
            return "PERMISSION_DENIED";
        }
        if (error instanceof IllegalArgumentException) {
            return "ILLEGAL_ARGUMENT";
        }
        if (error instanceof IllegalStateException) {
            return "ILLEGAL_STATE";
        }
        if (error instanceof UnsupportedOperationException) {
            return "UNSUPPORTED_OPERATION";
        }
        return "UNEXPECTED(" + error + ")";
    }

    private static void assertFails(String kind, String what, Supplier<Object> action) {
        Object result;
        try {
            result = action.get();
        } catch (RuntimeException e) {
            assertEquals(kind, errorKind(e), what);
            return;
        }
        fail(what + ": expected " + kind + ", but got " + result);
    }
}
