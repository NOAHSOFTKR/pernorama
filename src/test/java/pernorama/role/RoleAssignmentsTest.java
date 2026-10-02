package pernorama.role;

import org.junit.jupiter.api.Test;
import pernorama.exception.InvalidPermissionException;
import pernorama.permission.ContextPolicy;
import pernorama.subject.CompositePermissionSubject;
import pernorama.subject.MemoryPermissionSubject;
import pernorama.subject.PermissionSubject;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RoleAssignmentsTest {

    private static RoleGroup group(String id, int min, int max, RoleAssignmentPolicy policy) {
        return RoleGroup.builder(id).minAssignments(min).maxAssignments(max).assignmentPolicy(policy).build();
    }

    private static Role role(String id, RoleGroup group, String... rules) {
        Role.Builder builder = Role.builder(id);
        if (group != null) {
            builder.group(group);
        }
        for (String rule : rules) {
            builder.permission(rule);
        }
        return builder.build();
    }

    // --- exclusive groups -------------------------------------------------

    @Test
    void exclusiveGroupReplacesTheHeldRole() {
        RoleGroup plan = group("plan", 0, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        Role pro = role("plan_pro", plan, "app.use", "app.plan.pro");
        Role max5 = role("plan_max_5", plan, "app.use", "app.plan.max5");
        RoleAssignments<String> assignments = new RoleAssignments<>();

        RoleAssignmentResult first = assignments.assign("alice", pro);
        RoleAssignmentResult second = assignments.assign("alice", max5);

        assertEquals(RoleAssignmentStatus.ASSIGNED, first.status());
        assertEquals(Optional.of(pro), first.currentRole());
        assertEquals(Optional.empty(), first.previousRole());

        assertEquals(RoleAssignmentStatus.REPLACED, second.status());
        assertEquals(Optional.of(pro), second.previousRole());
        assertEquals(Optional.of(max5), second.currentRole());
        assertEquals(List.of(pro), second.removedRoles());
        assertEquals(Optional.of(plan), second.group());
        assertEquals(List.of(max5), assignments.roles("alice"));
    }

    @Test
    void exclusiveGroupRejectsWithTheRejectPolicy() {
        RoleGroup plan = group("plan", 0, 1, RoleAssignmentPolicy.REJECT);
        Role pro = role("plan_pro", plan);
        Role max5 = role("plan_max_5", plan);
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", pro);

        RoleAssignmentResult result = assignments.assign("alice", max5);

        assertEquals(RoleAssignmentStatus.REJECTED, result.status());
        assertTrue(result.rejectionReason().isPresent());
        assertEquals(Optional.empty(), result.currentRole());
        assertEquals(List.of(), result.removedRoles());
        assertEquals(List.of(pro), assignments.roles("alice"));
    }

    @Test
    void reassigningAHeldRoleIsIdempotent() {
        RoleGroup plan = group("plan", 0, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        Role pro = role("plan_pro", plan);
        AtomicInteger policyCalls = new AtomicInteger();
        RoleGroup counted = group("counted", 0, 1, (g, held, requested) -> {
            policyCalls.incrementAndGet();
            return RoleAssignmentDecision.replace(held);
        });
        Role countedRole = role("counted_role", counted);
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", pro);
        assignments.assign("alice", countedRole);

        RoleAssignmentResult again = assignments.assign("alice", pro);
        RoleAssignmentResult countedAgain = assignments.assign("alice", countedRole);

        assertEquals(RoleAssignmentStatus.NO_CHANGE, again.status());
        assertEquals(Optional.of(pro), again.currentRole());
        assertEquals(RoleAssignmentStatus.NO_CHANGE, countedAgain.status());
        assertEquals(0, policyCalls.get());
        assertEquals(List.of(pro, countedRole), assignments.roles("alice"));
    }

    @Test
    void groupsAreIndependentOfEachOther() {
        RoleGroup plan = group("plan", 0, 1, RoleAssignmentPolicy.REJECT);
        RoleGroup region = group("region", 0, 1, RoleAssignmentPolicy.REJECT);
        Role pro = role("plan_pro", plan);
        Role eu = role("region_eu", region);
        Role loose = role("beta_tester", null);
        RoleAssignments<String> assignments = new RoleAssignments<>();

        assertEquals(RoleAssignmentStatus.ASSIGNED, assignments.assign("alice", pro).status());
        assertEquals(RoleAssignmentStatus.ASSIGNED, assignments.assign("alice", eu).status());
        assertEquals(RoleAssignmentStatus.ASSIGNED, assignments.assign("alice", loose).status());
        assertEquals(RoleAssignmentStatus.ASSIGNED, assignments.assign("bob", pro).status());
    }

    // --- multi-assignment groups ---------------------------------------------

    @Test
    void groupAllowsUpToItsMaximum() {
        RoleGroup teams = group("teams", 0, 2, RoleAssignmentPolicy.REJECT);
        Role a = role("team_a", teams);
        Role b = role("team_b", teams);
        Role c = role("team_c", teams);
        RoleAssignments<String> assignments = new RoleAssignments<>();

        assertEquals(RoleAssignmentStatus.ASSIGNED, assignments.assign("alice", a).status());
        assertEquals(RoleAssignmentStatus.ASSIGNED, assignments.assign("alice", b).status());
        assertEquals(RoleAssignmentStatus.REJECTED, assignments.assign("alice", c).status());
        assertEquals(List.of(a, b), assignments.roles("alice"));
    }

    @Test
    void replaceOldestAndNewestPickByAssignmentOrder() {
        Role a;
        Role b;
        Role c;

        RoleGroup oldest = group("teams", 0, 2, RoleAssignmentPolicy.REPLACE_OLDEST);
        a = role("team_a", oldest);
        b = role("team_b", oldest);
        c = role("team_c", oldest);
        RoleAssignments<String> byOldest = new RoleAssignments<>();
        byOldest.assign("alice", a);
        byOldest.assign("alice", b);
        RoleAssignmentResult oldestResult = byOldest.assign("alice", c);

        assertEquals(RoleAssignmentStatus.REPLACED, oldestResult.status());
        assertEquals(List.of(a), oldestResult.removedRoles());
        assertEquals(List.of(b, c), byOldest.roles("alice"));

        RoleGroup newest = group("teams", 0, 2, RoleAssignmentPolicy.REPLACE_NEWEST);
        a = role("team_a", newest);
        b = role("team_b", newest);
        c = role("team_c", newest);
        RoleAssignments<String> byNewest = new RoleAssignments<>();
        byNewest.assign("alice", a);
        byNewest.assign("alice", b);
        RoleAssignmentResult newestResult = byNewest.assign("alice", c);

        assertEquals(List.of(b), newestResult.removedRoles());
        assertEquals(List.of(a, c), byNewest.roles("alice"));
    }

    @Test
    void replaceExistingInALargerGroupClearsIt() {
        RoleGroup teams = group("teams", 0, 2, RoleAssignmentPolicy.REPLACE_EXISTING);
        Role a = role("team_a", teams);
        Role b = role("team_b", teams);
        Role c = role("team_c", teams);
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", a);
        assignments.assign("alice", b);

        RoleAssignmentResult result = assignments.assign("alice", c);

        assertEquals(List.of(a, b), result.removedRoles());
        assertEquals(List.of(c), assignments.roles("alice"));
    }

    @Test
    void rolesOutsideTheGroupKeepTheirPlaceWhenReplacing() {
        RoleGroup plan = group("plan", 0, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        Role before = role("before", null);
        Role pro = role("plan_pro", plan);
        Role after = role("after", null);
        Role max5 = role("plan_max_5", plan);
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", before);
        assignments.assign("alice", pro);
        assignments.assign("alice", after);

        assignments.assign("alice", max5);

        assertEquals(List.of(before, after, max5), assignments.roles("alice"));
    }

    // --- minimum ---------------------------------------------------------------

    @Test
    void unassignRespectsTheMinimum() {
        RoleGroup plan = group("plan", 1, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        Role pro = role("plan_pro", plan);
        Role max5 = role("plan_max_5", plan);
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", pro);

        RoleAssignmentResult rejected = assignments.unassign("alice", pro);

        assertEquals(RoleAssignmentStatus.REJECTED, rejected.status());
        assertEquals(Optional.of(pro), rejected.currentRole());
        assertEquals(List.of(pro), assignments.roles("alice"));

        // replacing keeps the group at its minimum, so it is allowed
        assertEquals(RoleAssignmentStatus.REPLACED, assignments.assign("alice", max5).status());
    }

    @Test
    void unassignRemovesAndReportsTheRole() {
        Role loose = role("beta_tester", null);
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", loose);

        RoleAssignmentResult removed = assignments.unassign("alice", loose);
        RoleAssignmentResult again = assignments.unassign("alice", loose);

        assertEquals(RoleAssignmentStatus.UNASSIGNED, removed.status());
        assertEquals(Optional.of(loose), removed.previousRole());
        assertEquals(Optional.empty(), removed.currentRole());
        assertEquals(RoleAssignmentStatus.NO_CHANGE, again.status());
        assertEquals(List.of(), assignments.roles("alice"));
    }

    @Test
    void unassignCountsAgainstTheGroupOfTheStoredRole() {
        RoleGroup plan = group("plan", 1, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        Role pro = role("plan_pro", plan);
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", pro);

        RoleAssignmentResult result = assignments.unassign("alice", role("plan_pro", null));

        assertEquals(RoleAssignmentStatus.REJECTED, result.status());
        assertEquals(List.of(pro), assignments.roles("alice"));
    }

    @Test
    void startingBelowTheMinimumIsAllowed() {
        RoleGroup teams = group("teams", 2, 3, RoleAssignmentPolicy.REJECT);
        Role a = role("team_a", teams);
        RoleAssignments<String> assignments = new RoleAssignments<>();

        assertEquals(RoleAssignmentStatus.ASSIGNED, assignments.assign("alice", a).status());
    }

    // --- custom assignment policies ----------------------------------------------

    @Test
    void customAssignmentPolicyDecides() {
        Role vip = Role.builder("tier_vip").build();
        // keep the VIP tier, replace anything else
        RoleAssignmentPolicy keepVip = (group, held, requested) -> {
            List<Role> replaceable = new ArrayList<>();
            for (Role r : held) {
                if (!r.equals(vip)) {
                    replaceable.add(r);
                }
            }
            return replaceable.isEmpty()
                    ? RoleAssignmentDecision.reject("the VIP tier is never replaced")
                    : RoleAssignmentDecision.replace(replaceable.subList(0, 1));
        };
        RoleGroup tier = group("tier", 0, 1, keepVip);
        Role gold = role("tier_gold", tier);
        Role vipInTier = role("tier_vip", tier);
        Role silver = role("tier_silver", tier);
        RoleAssignments<String> assignments = new RoleAssignments<>();

        assignments.assign("alice", gold);
        assertEquals(RoleAssignmentStatus.REPLACED, assignments.assign("alice", silver).status());

        assignments.assign("bob", vipInTier);
        RoleAssignmentResult result = assignments.assign("bob", silver);
        assertEquals(RoleAssignmentStatus.REJECTED, result.status());
        assertEquals(Optional.of("the VIP tier is never replaced"), result.rejectionReason());
    }

    @Test
    void invalidPolicyDecisionsFailWithoutChangingAnything() {
        Role stranger = Role.builder("stranger").build();
        RoleAssignmentPolicy replacesNothing = (g, held, r) -> RoleAssignmentDecision.replace(List.of());
        RoleAssignmentPolicy replacesUnheld = (g, held, r) -> RoleAssignmentDecision.replace(List.of(stranger));
        RoleAssignmentPolicy replacesTwice = (g, held, r) -> RoleAssignmentDecision.replace(List.of(held.get(0), held.get(0)));
        RoleAssignmentPolicy returnsNull = (g, held, r) -> null;

        for (RoleAssignmentPolicy policy : List.of(replacesNothing, replacesUnheld, replacesTwice)) {
            RoleGroup g = group("g", 0, 1, policy);
            Role a = role("a", g);
            RoleAssignments<String> assignments = new RoleAssignments<>();
            assignments.assign("alice", a);

            assertThrows(IllegalStateException.class, () -> assignments.assign("alice", role("b", g)));
            assertEquals(List.of(a), assignments.roles("alice"));
        }

        RoleGroup g = group("g", 0, 1, returnsNull);
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", role("a", g));
        assertThrows(NullPointerException.class, () -> assignments.assign("alice", role("b", g)));
    }

    @Test
    void policyMayNotDropTheGroupUnderItsMinimum() {
        RoleAssignmentPolicy replaceAll = (g, held, requested) -> RoleAssignmentDecision.replace(held);
        RoleGroup teams = group("teams", 2, 2, replaceAll);
        Role a = role("team_a", teams);
        Role b = role("team_b", teams);
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", a);
        assignments.assign("alice", b);

        assertThrows(IllegalStateException.class, () -> assignments.assign("alice", role("team_c", teams)));
        assertEquals(List.of(a, b), assignments.roles("alice"));
    }

    // --- group definitions ------------------------------------------------------

    @Test
    void conflictingDefinitionsOfOneGroupFailInsteadOfBypassingItsLimits() {
        RoleGroup strict = group("plan", 0, 1, RoleAssignmentPolicy.REJECT);
        RoleGroup loose = group("plan", 0, 2, RoleAssignmentPolicy.REJECT);
        Role pro = role("plan_pro", strict);
        Role max5 = role("plan_max_5", loose);
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", pro);

        assertThrows(IllegalStateException.class, () -> assignments.assign("alice", max5));
        assertEquals(List.of(pro), assignments.roles("alice"));
    }

    @Test
    void conflictingPolicyAloneIsAConflict() {
        RoleGroup rejecting = group("plan", 0, 1, RoleAssignmentPolicy.REJECT);
        RoleGroup replacing = group("plan", 0, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        Role pro = role("plan_pro", rejecting);
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", pro);

        assertThrows(IllegalStateException.class, () -> assignments.assign("alice", role("plan_max_5", replacing)));
        assertThrows(IllegalStateException.class, () -> assignments.unassign("alice", role("plan_pro", replacing)));
        assertEquals(List.of(pro), assignments.roles("alice"));
    }

    @Test
    void separatelyBuiltButIdenticalDefinitionsAgree() {
        RoleGroup first = group("plan", 0, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        RoleGroup second = group("plan", 0, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        Role pro = role("plan_pro", first);
        Role max5 = role("plan_max_5", second);
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", pro);

        assertEquals(RoleAssignmentStatus.REPLACED, assignments.assign("alice", max5).status());
        assertEquals(List.of(max5), assignments.roles("alice"));
    }

    @Test
    void reassigningANewDefinitionOfAHeldRoleKeepsTheOldOne() {
        Role v1 = role("editor", null, "posts.edit");
        Role v2 = role("editor", null, "posts.edit", "posts.delete");
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", v1);

        assertEquals(RoleAssignmentStatus.NO_CHANGE, assignments.assign("alice", v2).status());
        assertFalse(assignments.subject("alice").hasPermission("posts.delete"));
    }

    // --- atomicity -----------------------------------------------------------

    @Test
    void replacementIsOneStoreWrite() {
        List<List<RoleAssignment>> writes = new ArrayList<>();
        MemoryRoleAssignmentStore<String> memory = new MemoryRoleAssignmentStore<>();
        RoleAssignmentStore<String> recording = new RoleAssignmentStore<>() {
            @Override
            public List<RoleAssignment> assignments(String target) {
                return memory.assignments(target);
            }

            @Override
            public boolean replace(String target, List<RoleAssignment> expected, List<RoleAssignment> updated) {
                writes.add(updated);
                return memory.replace(target, expected, updated);
            }
        };
        RoleGroup plan = group("plan", 0, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        Role pro = role("plan_pro", plan);
        Role max5 = role("plan_max_5", plan);
        RoleAssignments<String> assignments = new RoleAssignments<>(recording);
        assignments.assign("alice", pro);
        writes.clear();

        assignments.assign("alice", max5);

        assertEquals(List.of(List.of(new RoleAssignment(max5, null))), writes);
    }

    @Test
    void aLostRaceIsDecidedAgainFromTheFreshState() {
        RoleGroup plan = group("plan", 0, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        Role pro = role("plan_pro", plan);
        Role max5 = role("plan_max_5", plan);
        Role max20 = role("plan_max_20", plan);
        MemoryRoleAssignmentStore<String> memory = new MemoryRoleAssignmentStore<>();
        memory.replace("alice", List.of(), List.of(new RoleAssignment(pro, null)));
        AtomicInteger calls = new AtomicInteger();
        RoleAssignmentStore<String> racing = new RoleAssignmentStore<>() {
            @Override
            public List<RoleAssignment> assignments(String target) {
                return memory.assignments(target);
            }

            @Override
            public boolean replace(String target, List<RoleAssignment> expected, List<RoleAssignment> updated) {
                if (calls.getAndIncrement() == 0) {
                    // someone else switches the plan first
                    memory.replace(target, expected, List.of(new RoleAssignment(max20, null)));
                }
                return memory.replace(target, expected, updated);
            }
        };

        RoleAssignmentResult result = new RoleAssignments<>(racing).assign("alice", max5);

        assertEquals(RoleAssignmentStatus.REPLACED, result.status());
        assertEquals(Optional.of(max20), result.previousRole());
        assertEquals(List.of(new RoleAssignment(max5, null)), memory.assignments("alice"));
    }

    @Test
    void concurrentAssignmentsToAnExclusiveGroupLeaveExactlyOneRole() throws Exception {
        RoleGroup plan = group("plan", 0, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        List<Role> plans = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            plans.add(role("plan_" + i, plan));
        }
        RoleAssignments<String> assignments = new RoleAssignments<>();
        ExecutorService pool = Executors.newFixedThreadPool(plans.size());
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (Role p : plans) {
                futures.add(pool.submit(() -> {
                    start.await();
                    for (int i = 0; i < 200; i++) {
                        assignments.assign("alice", p);
                        assertEquals(1, assignments.roles("alice").size());
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> future : futures) {
                future.get(30, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }

        assertEquals(1, assignments.roles("alice").size());
    }

    // --- permission resolution -------------------------------------------------

    @Test
    void subjectCombinesHeldRolesAndFollowsAssignments() {
        RoleGroup plan = group("plan", 0, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        Role pro = role("plan_pro", plan, "app.use", "app.plan.pro");
        Role max5 = role("plan_max_5", plan, "app.use", "app.plan.max5");
        Role support = role("support", null, "tickets.*");
        RoleAssignments<String> assignments = new RoleAssignments<>();
        PermissionSubject alice = assignments.subject("alice");

        assertFalse(alice.hasPermission("app.use"));

        assignments.assign("alice", pro);
        assignments.assign("alice", support);
        assertTrue(alice.hasPermission("app.plan.pro"));
        assertTrue(alice.hasPermission("tickets.close"));

        assignments.assign("alice", max5);
        assertFalse(alice.hasPermission("app.plan.pro"));
        assertTrue(alice.hasPermission("app.plan.max5"));
    }

    @Test
    void allowOverridesMatchesCompositePermissionSubject() {
        Role restricted = role("restricted", null, "users.*", "-users.delete");
        Role deleter = role("deleter", null, "users.delete");
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", restricted);
        assignments.assign("alice", deleter);

        PermissionSubject viaRoles = assignments.subject("alice");
        PermissionSubject viaComposite = new CompositePermissionSubject(
                restricted.permissions(), deleter.permissions());

        for (String node : List.of("users.read", "users.delete", "users.delete.hard", "posts.read")) {
            assertEquals(viaComposite.hasPermission(node), viaRoles.hasPermission(node), node);
        }
        assertTrue(viaRoles.hasPermission("users.delete"));
    }

    @Test
    void denyOverridesLetsOneRoleVetoAnother() {
        Role restricted = role("restricted", null, "users.*", "-users.delete");
        Role deleter = role("deleter", null, "users.delete");
        Role unrelated = role("unrelated", null, "posts.read");
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", restricted);
        assignments.assign("alice", deleter);
        assignments.assign("alice", unrelated);

        PermissionSubject alice = assignments.subject("alice", PermissionResolutionPolicy.DENY_OVERRIDES);

        assertFalse(alice.hasPermission("users.delete")); // vetoed by restricted
        assertTrue(alice.hasPermission("users.read"));    // unrelated does not veto by omission
        assertTrue(alice.hasPermission("posts.read"));
        assertFalse(alice.hasPermission("admin.read"));
    }

    @Test
    void denyOverridesIsOrderIndependent() {
        Role restricted = role("restricted", null, "users.*", "-users.delete");
        Role deleter = role("deleter", null, "users.delete");

        RoleAssignment r = new RoleAssignment(restricted, null);
        RoleAssignment d = new RoleAssignment(deleter, null);

        assertFalse(PermissionResolutionPolicy.DENY_OVERRIDES.hasPermission(List.of(r, d), "users.delete", null));
        assertFalse(PermissionResolutionPolicy.DENY_OVERRIDES.hasPermission(List.of(d, r), "users.delete", null));
    }

    @Test
    void customResolutionPolicyIsUsed() {
        RoleGroup plan = group("plan", 0, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        Role pro = role("plan_pro", plan, "app.*");
        Role banned = role("banned", null);
        // a "banned" role blocks everything, whatever else is held
        PermissionResolutionPolicy bannedBlocks = (held, node, context) ->
                held.stream().noneMatch(a -> a.role().equals(banned))
                        && PermissionResolutionPolicy.ALLOW_OVERRIDES.hasPermission(held, node, context);
        RoleAssignments<String> assignments = new RoleAssignments<>();
        PermissionSubject alice = assignments.subject("alice", bannedBlocks);
        assignments.assign("alice", pro);

        assertTrue(alice.hasPermission("app.use"));
        assignments.assign("alice", banned);
        assertFalse(alice.hasPermission("app.use"));
    }

    @Test
    void subjectIsReadOnlyAndValidatesNodes() {
        RoleAssignments<String> assignments = new RoleAssignments<>();
        PermissionSubject alice = assignments.subject("alice");

        assertThrows(UnsupportedOperationException.class, () -> alice.grant("users.read"));
        assertThrows(UnsupportedOperationException.class, () -> alice.revoke("users.read"));
        assertThrows(InvalidPermissionException.class, () -> alice.hasPermission("users..read"));
        assertThrows(InvalidPermissionException.class, () -> alice.hasPermission("-users.read"));
    }

    @Test
    void subjectComposesWithDirectGrants() {
        Role reader = role("reader", null, "posts.read");
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", reader);
        PermissionSubject own = new MemoryPermissionSubject(List.of("profile.edit"));

        PermissionSubject alice = new CompositePermissionSubject(own, assignments.subject("alice"));

        assertTrue(alice.hasPermission("posts.read"));
        assertTrue(alice.hasPermission("profile.edit"));
    }

    @Test
    void nullArgumentsAreRejected() {
        RoleAssignments<String> assignments = new RoleAssignments<>();
        Role r = role("r", null);

        assertThrows(NullPointerException.class, () -> new RoleAssignments<String>(null));
        assertThrows(NullPointerException.class, () -> assignments.assign(null, r));
        assertThrows(NullPointerException.class, () -> assignments.assign("alice", null));
        assertThrows(NullPointerException.class, () -> assignments.unassign(null, r));
        assertThrows(NullPointerException.class, () -> assignments.roles(null));
        assertThrows(NullPointerException.class, () -> assignments.subject(null));
        assertThrows(NullPointerException.class, () -> assignments.subject("alice", null));
    }

    @Test
    void rolesViewIsUnmodifiable() {
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", role("r", null));

        assertThrows(UnsupportedOperationException.class, () -> assignments.roles("alice").clear());
    }

    // --- contexts -------------------------------------------------------------

    private static final String A123 = "academy:123";
    private static final String A456 = "academy:456";

    @Test
    void theSameRoleCanBeHeldInSeveralContexts() {
        Role teacher = role("teacher", null, "students.*");
        RoleAssignments<String> assignments = new RoleAssignments<>();

        assertEquals(RoleAssignmentStatus.ASSIGNED, assignments.assign("alice", teacher, A123).status());
        assertEquals(RoleAssignmentStatus.ASSIGNED, assignments.assign("alice", teacher, A456).status());
        assertEquals(RoleAssignmentStatus.NO_CHANGE, assignments.assign("alice", teacher, A123).status());

        assertEquals(List.of(teacher), assignments.roles("alice", A123));
        assertEquals(List.of(teacher), assignments.roles("alice", A456));
        assertEquals(List.of(), assignments.roles("alice"));
        assertEquals(List.of(new RoleAssignment(teacher, A123), new RoleAssignment(teacher, A456)),
                assignments.assignments("alice"));
    }

    @Test
    void groupLimitsAreCountedPerContext() {
        RoleGroup membership = group("membership", 0, 1, RoleAssignmentPolicy.REJECT);
        Role teacher = role("teacher", membership);
        Role student = role("student", membership);
        RoleAssignments<String> assignments = new RoleAssignments<>();

        assertEquals(RoleAssignmentStatus.ASSIGNED, assignments.assign("alice", teacher, A123).status());
        assertEquals(RoleAssignmentStatus.ASSIGNED, assignments.assign("alice", student, A456).status());
        assertEquals(RoleAssignmentStatus.ASSIGNED, assignments.assign("alice", student).status());
        assertEquals(RoleAssignmentStatus.REJECTED, assignments.assign("alice", student, A123).status());
    }

    @Test
    void aReplacementStaysInItsContext() {
        RoleGroup membership = group("membership", 0, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        Role teacher = role("teacher", membership);
        Role student = role("student", membership);
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", teacher, A123);
        assignments.assign("alice", teacher, A456);

        RoleAssignmentResult result = assignments.assign("alice", student, A123);

        assertEquals(RoleAssignmentStatus.REPLACED, result.status());
        assertEquals(Optional.of(A123), result.context());
        assertEquals(List.of(teacher), result.removedRoles());
        assertEquals(List.of(student), assignments.roles("alice", A123));
        assertEquals(List.of(teacher), assignments.roles("alice", A456));
    }

    @Test
    void unassignTouchesOnlyThatContext() {
        RoleGroup membership = group("membership", 1, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        Role teacher = role("teacher", membership);
        Role reader = role("reader", null);
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", reader, A123);
        assignments.assign("alice", reader, A456);
        assignments.assign("alice", teacher, A123);

        RoleAssignmentResult unassigned = assignments.unassign("alice", reader, A123);
        RoleAssignmentResult notHeld = assignments.unassign("alice", reader);
        RoleAssignmentResult belowMinimum = assignments.unassign("alice", teacher, A123);

        assertEquals(RoleAssignmentStatus.UNASSIGNED, unassigned.status());
        assertEquals(Optional.of(A123), unassigned.context());
        assertEquals(List.of(reader), assignments.roles("alice", A456));
        assertEquals(RoleAssignmentStatus.NO_CHANGE, notHeld.status());
        assertEquals(Optional.empty(), notHeld.context());
        assertEquals(RoleAssignmentStatus.REJECTED, belowMinimum.status());
        assertTrue(belowMinimum.rejectionReason().orElseThrow().contains(A123));
        assertEquals(List.of(teacher), assignments.roles("alice", A123));
    }

    @Test
    void underGlobalFallbackARoleWithoutAContextAppliesEverywhere() {
        Role staff = role("staff", null, "students.read");
        Role teacher = role("teacher", null, "students.edit");
        RoleAssignments<String> assignments = new RoleAssignments<>(
                new MemoryRoleAssignmentStore<>(), ContextPolicy.GLOBAL_FALLBACK);
        assignments.assign("alice", staff);
        assignments.assign("alice", teacher, A123);
        PermissionSubject alice = assignments.subject("alice");

        assertTrue(alice.hasPermission("students.read"));
        assertTrue(alice.hasPermission("students.read", A123));
        assertTrue(alice.hasPermission("students.read", A456));
        assertTrue(alice.hasPermission("students.edit", A123));
        assertFalse(alice.hasPermission("students.edit", A456));
        assertFalse(alice.hasPermission("students.edit"));
    }

    @Test
    void underExactOnlyRolesInTheCheckedContextApply() {
        Role staff = role("staff", null, "students.read");
        Role teacher = role("teacher", null, "students.edit");
        RoleAssignments<String> assignments = new RoleAssignments<>(
                new MemoryRoleAssignmentStore<>(), ContextPolicy.EXACT);
        assignments.assign("alice", staff);
        assignments.assign("alice", teacher, A123);
        PermissionSubject alice = assignments.subject("alice");

        assertTrue(alice.hasPermission("students.read"));
        assertFalse(alice.hasPermission("students.read", A123));
        assertTrue(alice.hasPermission("students.edit", A123));
        assertFalse(alice.hasPermission("students.edit"));
    }

    @Test
    void aRoleBackedBySubjectIsAskedWithoutAContext() {
        MemoryPermissionSubject source = new MemoryPermissionSubject();
        source.grant("students.read");
        source.grant("students.edit", A456);
        Role teacher = Role.builder("teacher").permissions(source).build();
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", teacher, A123);
        PermissionSubject alice = assignments.subject("alice");

        assertTrue(alice.hasPermission("students.read", A123));
        assertFalse(alice.hasPermission("students.edit", A123));
        assertFalse(alice.hasPermission("students.edit", A456)); // the role is not held there
    }

    @Test
    void resolutionPoliciesCombineOnlyTheApplicableRoles() {
        Role editor = role("editor", null, "users.*");
        Role suspended = role("suspended", null, "-users.delete");
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("bob", editor);
        assignments.assign("bob", suspended, A123);

        PermissionSubject allow = assignments.subject("bob");
        PermissionSubject deny = assignments.subject("bob", PermissionResolutionPolicy.DENY_OVERRIDES);

        assertTrue(allow.hasPermission("users.delete", A123));
        assertFalse(deny.hasPermission("users.delete", A123));
        assertTrue(deny.hasPermission("users.delete", A456));
        assertTrue(deny.hasPermission("users.delete"));
    }

    @Test
    void aCustomResolutionPolicySeesTheApplicableAssignmentsAndTheContext() {
        Role staff = role("staff", null, "a.read");
        Role teacher = role("teacher", null, "a.read");
        Role other = role("other", null, "a.read");
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", staff);
        assignments.assign("alice", teacher, A123);
        assignments.assign("alice", other, A456);
        List<Object> seen = new ArrayList<>();
        PermissionResolutionPolicy recording = (held, node, context) -> {
            seen.add(held);
            seen.add(node);
            seen.add(context);
            return false;
        };

        assignments.subject("alice", recording).hasPermission("a.read", A123);

        assertEquals(List.of(
                List.of(new RoleAssignment(staff, null), new RoleAssignment(teacher, A123)), "a.read", A123), seen);
    }

    @Test
    void anEmptyContextIsRejected() {
        Role r = role("r", null);
        RoleAssignments<String> assignments = new RoleAssignments<>();

        assertThrows(IllegalArgumentException.class, () -> assignments.assign("alice", r, ""));
        assertThrows(IllegalArgumentException.class, () -> assignments.unassign("alice", r, ""));
        assertThrows(IllegalArgumentException.class, () -> assignments.roles("alice", ""));
        assertThrows(IllegalArgumentException.class, () -> assignments.subject("alice").hasPermission("a.read", ""));
        assertThrows(IllegalArgumentException.class, () -> new RoleAssignment(r, ""));
        assertThrows(NullPointerException.class, () -> new RoleAssignment(null, A123));
    }

    @Test
    void assignmentsAndResultsShowTheirContext() {
        Role teacher = role("teacher", null);

        assertEquals("teacher @ academy:123", new RoleAssignment(teacher, A123).toString());
        assertEquals("teacher", new RoleAssignment(teacher, null).toString());
        assertTrue(new RoleAssignments<String>().assign("alice", teacher, A123).toString()
                .contains("context=academy:123"));
    }

    @Test
    void replaceOldestPicksByOrderWithinTheContextOnly() {
        RoleGroup teams = group("teams", 0, 2, RoleAssignmentPolicy.REPLACE_OLDEST);
        Role a = role("team_a", teams);
        Role b = role("team_b", teams);
        Role c = role("team_c", teams);
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", a, A456); // oldest overall, but in another context
        assignments.assign("alice", b, A123);
        assignments.assign("alice", a, A123);

        RoleAssignmentResult result = assignments.assign("alice", c, A123);

        assertEquals(List.of(b), result.removedRoles());
        assertEquals(List.of(a, c), assignments.roles("alice", A123));
        assertEquals(List.of(a), assignments.roles("alice", A456));
    }

    @Test
    void aPolicyCannotReplaceARoleHeldInAnotherContext() {
        Role[] elsewhere = new Role[1];
        // a buggy policy that always replaces the role held in academy:456
        RoleGroup membership = group("membership", 0, 1,
                (g, held, requested) -> RoleAssignmentDecision.replace(List.of(elsewhere[0])));
        Role x = role("member_x", membership);
        Role y = role("member_y", membership);
        Role z = role("member_z", membership);
        elsewhere[0] = x;
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", x, A456);
        assignments.assign("alice", y, A123);

        assertThrows(IllegalStateException.class, () -> assignments.assign("alice", z, A123));
        assertEquals(List.of(y), assignments.roles("alice", A123));
        assertEquals(List.of(x), assignments.roles("alice", A456));
    }

    @Test
    void aConflictingGroupDefinitionFailsEvenWhenHeldInAnotherContext() {
        Role loose = role("team_a", group("teams", 0, 5, RoleAssignmentPolicy.REJECT));
        Role strict = role("team_b", group("teams", 0, 1, RoleAssignmentPolicy.REJECT));
        RoleAssignments<String> assignments = new RoleAssignments<>();
        assignments.assign("alice", loose, A456);

        assertThrows(IllegalStateException.class, () -> assignments.assign("alice", strict, A123));
        assertEquals(List.of(), assignments.roles("alice", A123));
    }

    @Test
    void denyOverridesUnderExactIgnoresRolesHeldElsewhere() {
        Role editor = role("editor", null, "users.*");
        Role suspended = role("suspended", null, "-users.delete");
        RoleAssignments<String> assignments = new RoleAssignments<>(new MemoryRoleAssignmentStore<>(), ContextPolicy.EXACT);
        assignments.assign("bob", editor, A123);
        assignments.assign("bob", suspended);
        PermissionSubject bob = assignments.subject("bob", PermissionResolutionPolicy.DENY_OVERRIDES);

        assertTrue(bob.hasPermission("users.delete", A123));
        assertFalse(bob.hasPermission("users.delete"));
        assertFalse(bob.hasPermission("users.read"));
    }

    @Test
    void concurrentAssignmentsKeepEachContextWithinItsLimits() throws Exception {
        RoleGroup membership = group("membership", 0, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        List<Role> roles = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            roles.add(role("member_" + i, membership));
        }
        List<String> contexts = List.of(A123, A456, "academy:789");
        RoleAssignments<String> assignments = new RoleAssignments<>();
        ExecutorService pool = Executors.newFixedThreadPool(roles.size() * contexts.size());
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (String context : contexts) {
                for (Role r : roles) {
                    futures.add(pool.submit(() -> {
                        start.await();
                        for (int i = 0; i < 100; i++) {
                            assignments.assign("alice", r, context);
                            assertEquals(1, assignments.roles("alice", context).size());
                        }
                        return null;
                    }));
                }
            }
            start.countDown();
            for (Future<?> future : futures) {
                future.get(30, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }

        for (String context : contexts) {
            assertEquals(1, assignments.roles("alice", context).size());
        }
        assertEquals(contexts.size(), assignments.assignments("alice").size());
    }
}
