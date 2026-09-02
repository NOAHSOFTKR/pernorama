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
import pernorama.subject.MemoryPermissionSubject;
import pernorama.subject.PermissionSubject;

import java.util.HashSet;
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

        assertThrows(InvalidPermissionException.class, () -> PermissionNode.of("users..create"));
        assertThrows(InvalidPermissionException.class, () -> PermissionNode.of(".users"));
        assertThrows(InvalidPermissionException.class, () -> PermissionNode.of("users."));
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

    @PermGroup("users")
    static class UserPermissions {

        @Perm("create")
        public void create() {
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
        assertFalse(registry.validate("users.delete"));
        assertEquals(Set.of(PermissionNode.of("users.create")), Set.copyOf(registry.all()));
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
}
