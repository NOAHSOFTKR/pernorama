package pernorama.permission;

import org.junit.jupiter.api.Test;
import pernorama.fixture.UserPermissions;
import pernorama.fixture.UserService;

import java.util.NoSuchElementException;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionRegistryTest {

    @Test
    void recognizesPermGroupAndPrefixesMemberPermissions() {
        PermissionRegistry registry = new PermissionRegistry();

        Set<PermissionNode> registered = registry.register(UserPermissions.class);

        assertEquals(Set.of(PermissionNode.of("users.create"), PermissionNode.of("users.delete")), registered);
        assertTrue(registry.contains("users.create"));
        assertTrue(registry.contains("users.delete"));
    }

    @Test
    void recognizesPermWithoutGroupAsFullyQualified() {
        PermissionRegistry registry = new PermissionRegistry();

        Set<PermissionNode> registered = registry.register(UserService.class);

        assertEquals(Set.of(PermissionNode.of("users.create")), registered);
        assertTrue(registry.contains("users.create"));
    }

    @Test
    void getReturnsRegisteredNode() {
        PermissionRegistry registry = new PermissionRegistry();
        registry.register(UserPermissions.class);

        assertEquals(PermissionNode.of("users.create"), registry.get("users.create"));
    }

    @Test
    void getThrowsForUnknownNode() {
        PermissionRegistry registry = new PermissionRegistry();

        assertThrows(NoSuchElementException.class, () -> registry.get("users.create"));
    }

    @Test
    void allAccumulatesAcrossRegisterCalls() {
        PermissionRegistry registry = new PermissionRegistry();
        registry.register(UserPermissions.class);
        registry.register(UserService.class);

        assertEquals(2, registry.all().size());
    }
}
