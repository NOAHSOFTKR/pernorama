package pernorama;

import org.junit.jupiter.api.Test;
import pernorama.annotation.Perm;
import pernorama.annotation.PermGroup;
import pernorama.exception.InvalidPermissionException;
import pernorama.exception.PermissionDeniedException;
import pernorama.interceptor.PermissionInterceptor;
import pernorama.permission.Permission;
import pernorama.permission.PermissionNode;
import pernorama.permission.PermissionRegistry;
import pernorama.permission.PermissionResolver;
import pernorama.role.PermissionResolutionPolicy;
import pernorama.role.Role;
import pernorama.role.RoleAssignmentDecision;
import pernorama.role.RoleAssignmentPolicy;
import pernorama.role.RoleAssignmentResult;
import pernorama.role.RoleAssignmentStatus;
import pernorama.role.RoleAssignments;
import pernorama.role.RoleGroup;
import pernorama.subject.CompositePermissionSubject;
import pernorama.subject.MemoryPermissionSubject;
import pernorama.subject.PermissionSubject;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every code sample here is transcribed verbatim into README.md. Keeping
 * them here as compiled, executed tests means the README can't silently
 * drift from the actual public API.
 */
class ReadmeExamplesTest {

    static class UserService {

        @Perm("users.create")
        public void createUser() {
        }
    }

    @Test
    void quickStart() {
        PermissionSubject user = new MemoryPermissionSubject();
        user.grant("users.create");

        PermissionInterceptor interceptor = new PermissionInterceptor();
        UserService userService = new UserService();

        assertDoesNotThrow(() -> interceptor.invoke(user, userService, "createUser"));

        user.revoke("users.create");

        assertThrows(PermissionDeniedException.class,
                () -> interceptor.invoke(user, userService, "createUser"));
    }

    @Test
    void permissionNodes() {
        PermissionNode node = PermissionNode.of("users.create");
        assertEquals("users.create", node.name());
        assertEquals(Optional.of(PermissionNode.of("users")), node.parent());
        assertTrue(node.isChildOf(PermissionNode.of("users")));

        assertThrows(InvalidPermissionException.class, () -> PermissionNode.of(""));
        assertThrows(InvalidPermissionException.class, () -> PermissionNode.of(" "));
        assertThrows(InvalidPermissionException.class, () -> PermissionNode.of(".users"));
        assertThrows(InvalidPermissionException.class, () -> PermissionNode.of("users."));
        assertThrows(InvalidPermissionException.class, () -> PermissionNode.of("users..create"));
        assertThrows(InvalidPermissionException.class, () -> PermissionNode.of("users create"));
        assertThrows(InvalidPermissionException.class, () -> PermissionNode.of("-users.create"));
    }

    @Test
    void wildcards() {
        PermissionSubject admin = new MemoryPermissionSubject();
        admin.grant("users.*");

        assertTrue(admin.hasPermission("users.create"));
        assertTrue(admin.hasPermission("users.profile.read"));
        assertFalse(admin.hasPermission("admin.read"));

        PermissionSubject root = new MemoryPermissionSubject();
        root.grant("*");

        assertTrue(root.hasPermission("anything.at.all"));
    }

    @Test
    void denyRules() {
        PermissionSubject moderator = new MemoryPermissionSubject();
        moderator.grant("users.*");
        moderator.grant("-users.delete");

        assertTrue(moderator.hasPermission("users.create"));
        assertFalse(moderator.hasPermission("users.delete"));

        PermissionSubject auditor = new MemoryPermissionSubject();
        auditor.grant("*");
        auditor.grant("-users.*");
        auditor.grant("users.read");

        assertTrue(auditor.hasPermission("posts.read"));
        assertFalse(auditor.hasPermission("users.create"));
        assertTrue(auditor.hasPermission("users.read"));

        PermissionSubject editor = new MemoryPermissionSubject();
        editor.grant("users.*");
        editor.grant("-users.delete.*");

        assertFalse(editor.hasPermission("users.delete"));
        assertFalse(editor.hasPermission("users.delete.hard"));

        PermissionSubject exactOnly = new MemoryPermissionSubject(List.of("users.*", "-users.delete"));
        assertTrue(exactOnly.hasPermission("users.delete.hard"));

        moderator.revoke("-users.delete");
        assertTrue(moderator.hasPermission("users.delete"));

        assertTrue(PermissionNode.isValid("users.soft-delete"));
    }

    @PermGroup("users")
    static class UserPermissions {

        @Perm("create")
        public void create() {
        }

        @Perm("delete")
        public void delete() {
        }
    }

    static class OverridingUserPermissions extends UserPermissions {

        @Override
        public void create() {
        }
    }

    @Test
    void annotationsAndGroups() {
        PermissionInterceptor interceptor = new PermissionInterceptor();
        PermissionSubject user = new MemoryPermissionSubject();
        UserPermissions userPermissions = new UserPermissions();

        assertThrows(PermissionDeniedException.class,
                () -> interceptor.invoke(user, userPermissions, "create"));

        user.grant("users.create");
        assertDoesNotThrow(() -> interceptor.invoke(user, userPermissions, "create"));

        // Overriding create() without redeclaring @Perm drops the requirement.
        PermissionSubject noPermissions = new MemoryPermissionSubject();
        OverridingUserPermissions overriding = new OverridingUserPermissions();
        assertDoesNotThrow(() -> interceptor.invoke(noPermissions, overriding, "create"));
    }

    @Test
    void checkAndRequire() {
        PermissionSubject user = new MemoryPermissionSubject();
        user.grant("users.create");

        boolean allowed = Permission.check(user, "users.create");
        assertTrue(allowed);

        assertDoesNotThrow(() -> Permission.require(user, "users.create"));
        assertThrows(PermissionDeniedException.class, () -> Permission.require(user, "users.delete"));
    }

    @Test
    void permissionRegistry() {
        PermissionRegistry registry = new PermissionRegistry();

        registry.register(UserPermissions.class);

        assertTrue(registry.contains("users.create"));
        assertTrue(registry.validate("users.create"));
        assertFalse(registry.validate("users.delete_all"));
        assertEquals(
                Set.of(PermissionNode.of("users.create"), PermissionNode.of("users.delete")),
                Set.copyOf(registry.all()));
    }

    /** A minimal, storage-agnostic implementation for illustration. */
    static class DatabaseUser implements PermissionSubject {

        private final Set<String> permissions = new HashSet<>();

        @Override
        public boolean hasPermission(String node) {
            return PermissionResolver.matchesAny(permissions, node);
        }

        @Override
        public void grant(String node) {
            permissions.add(node);
        }

        @Override
        public void revoke(String node) {
            permissions.remove(node);
        }
    }

    @Test
    void customPermissionSubject() {
        DatabaseUser user = new DatabaseUser();
        user.grant("users.*");

        assertTrue(user.hasPermission("users.create"));
        assertTrue(Permission.check(user, "users.create"));
    }

    @Test
    void rolesAndComposition() {
        PermissionSubject admins = new MemoryPermissionSubject(List.of("users.*"));
        PermissionSubject own = new MemoryPermissionSubject(List.of("profile.edit"));

        PermissionSubject user = new CompositePermissionSubject(own, admins);

        assertTrue(user.hasPermission("users.create"));
        assertTrue(user.hasPermission("profile.edit"));
        assertFalse(user.hasPermission("posts.delete"));

        assertThrows(UnsupportedOperationException.class, () -> user.grant("posts.delete"));
        assertThrows(UnsupportedOperationException.class, () -> user.revoke("users.create"));
    }

    @Test
    void roleGroupsAndAssignments() {
        RoleGroup plan = RoleGroup.builder("plan")
                .minAssignments(0)
                .maxAssignments(1)
                .assignmentPolicy(RoleAssignmentPolicy.REPLACE_EXISTING)
                .build();

        Role pro = Role.builder("plan_pro")
                .group(plan)
                .permission("app.use")
                .permission("app.plan.pro")
                .build();

        Role max5 = Role.builder("plan_max_5")
                .group(plan)
                .permission("app.use")
                .permission("app.plan.max5")
                .build();

        RoleAssignments<String> assignments = new RoleAssignments<>();

        assertEquals(RoleAssignmentStatus.ASSIGNED, assignments.assign("alice", pro).status());
        RoleAssignmentResult result = assignments.assign("alice", max5);

        assertEquals(RoleAssignmentStatus.REPLACED, result.status());
        assertEquals(Optional.of(pro), result.previousRole());
        assertEquals(Optional.of(max5), result.currentRole());
        assertEquals(List.of(max5), assignments.roles("alice"));
        assertEquals("[plan_max_5]", assignments.roles("alice").toString());

        PermissionSubject alice = assignments.subject("alice");
        assertTrue(alice.hasPermission("app.plan.max5"));
        assertFalse(alice.hasPermission("app.plan.pro"));

        assertEquals(RoleAssignmentStatus.NO_CHANGE, assignments.assign("alice", max5).status());
    }

    @Test
    void customRoleAssignmentPolicy() {
        RoleAssignmentPolicy keepLifetime = (group, held, requested) ->
                held.stream().anyMatch(r -> r.id().equals("plan_lifetime"))
                        ? RoleAssignmentDecision.reject("lifetime plans are never replaced")
                        : RoleAssignmentDecision.replace(held);

        RoleGroup plan = RoleGroup.builder("plan").maxAssignments(1).assignmentPolicy(keepLifetime).build();
        Role lifetime = Role.builder("plan_lifetime").group(plan).build();
        Role pro = Role.builder("plan_pro").group(plan).build();
        RoleAssignments<String> assignments = new RoleAssignments<>();

        assignments.assign("alice", pro);
        assertEquals(RoleAssignmentStatus.REPLACED, assignments.assign("alice", lifetime).status());
        assertEquals(RoleAssignmentStatus.REJECTED, assignments.assign("alice", pro).status());
        assertEquals(List.of(lifetime), assignments.roles("alice"));
    }

    @Test
    void permissionResolutionPolicies() {
        RoleAssignments<String> assignments = new RoleAssignments<>();

        Role editor = Role.builder("editor").permission("users.*").build();
        Role suspended = Role.builder("suspended").permission("-users.delete").build();

        assignments.assign("bob", editor);
        assignments.assign("bob", suspended);

        assertTrue(assignments.subject("bob").hasPermission("users.delete"));
        assertFalse(assignments.subject("bob", PermissionResolutionPolicy.DENY_OVERRIDES)
                .hasPermission("users.delete"));
    }
}
