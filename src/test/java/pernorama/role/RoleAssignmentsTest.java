package pernorama.role;

import org.junit.jupiter.api.Test;
import pernorama.exception.InvalidPermissionException;
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

    // --- atomicity -----------------------------------------------------------

    @Test
    void replacementIsOneStoreWrite() {
        List<List<Role>> writes = new ArrayList<>();
        MemoryRoleAssignmentStore<String> memory = new MemoryRoleAssignmentStore<>();
        RoleAssignmentStore<String> recording = new RoleAssignmentStore<>() {
            @Override
            public List<Role> roles(String target) {
                return memory.roles(target);
            }

            @Override
            public boolean replace(String target, List<Role> expected, List<Role> updated) {
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

        assertEquals(List.of(List.of(max5)), writes);
    }

    @Test
    void aLostRaceIsDecidedAgainFromTheFreshState() {
        RoleGroup plan = group("plan", 0, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        Role pro = role("plan_pro", plan);
        Role max5 = role("plan_max_5", plan);
        Role max20 = role("plan_max_20", plan);
        MemoryRoleAssignmentStore<String> memory = new MemoryRoleAssignmentStore<>();
        memory.replace("alice", List.of(), List.of(pro));
        AtomicInteger calls = new AtomicInteger();
        RoleAssignmentStore<String> racing = new RoleAssignmentStore<>() {
            @Override
            public List<Role> roles(String target) {
                return memory.roles(target);
            }

            @Override
            public boolean replace(String target, List<Role> expected, List<Role> updated) {
                if (calls.getAndIncrement() == 0) {
                    // someone else switches the plan first
                    memory.replace(target, expected, List.of(max20));
                }
                return memory.replace(target, expected, updated);
            }
        };

        RoleAssignmentResult result = new RoleAssignments<>(racing).assign("alice", max5);

        assertEquals(RoleAssignmentStatus.REPLACED, result.status());
        assertEquals(Optional.of(max20), result.previousRole());
        assertEquals(List.of(max5), memory.roles("alice"));
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

        assertFalse(PermissionResolutionPolicy.DENY_OVERRIDES.hasPermission(List.of(restricted, deleter), "users.delete"));
        assertFalse(PermissionResolutionPolicy.DENY_OVERRIDES.hasPermission(List.of(deleter, restricted), "users.delete"));
    }

    @Test
    void customResolutionPolicyIsUsed() {
        RoleGroup plan = group("plan", 0, 1, RoleAssignmentPolicy.REPLACE_EXISTING);
        Role pro = role("plan_pro", plan, "app.*");
        Role banned = role("banned", null);
        // a "banned" role blocks everything, whatever else is held
        PermissionResolutionPolicy bannedBlocks = (roles, node) ->
                !roles.contains(banned) && PermissionResolutionPolicy.ALLOW_OVERRIDES.hasPermission(roles, node);
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
}
