package pernorama.permission;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionResolverTest {

    @Test
    void exactPatternMatchesOnlyItself() {
        assertTrue(PermissionResolver.matches("users.create", "users.create"));
        assertFalse(PermissionResolver.matches("users.create", "users.delete"));
    }

    @Test
    void globalWildcardMatchesAnything() {
        assertTrue(PermissionResolver.matches("*", "users.create"));
        assertTrue(PermissionResolver.matches("*", "posts.delete"));
        assertTrue(PermissionResolver.matches("*", "anything.at.all"));
    }

    @Test
    void groupWildcardMatchesItsChildren() {
        assertTrue(PermissionResolver.matches("users.*", "users.create"));
        assertTrue(PermissionResolver.matches("users.*", "users.delete"));
        assertTrue(PermissionResolver.matches("users.*", "users.update"));
        assertTrue(PermissionResolver.matches("users.*", "users.create.special"));
    }

    @Test
    void groupWildcardDoesNotMatchUnrelatedGroups() {
        assertFalse(PermissionResolver.matches("users.*", "posts.create"));
        assertFalse(PermissionResolver.matches("users.*", "userservice.create"));
    }

    @Test
    void matchesAnyChecksEveryPattern() {
        List<String> granted = List.of("posts.read", "users.*");

        assertTrue(PermissionResolver.matchesAny(granted, "users.create"));
        assertTrue(PermissionResolver.matchesAny(granted, "posts.read"));
        assertFalse(PermissionResolver.matchesAny(granted, "posts.delete"));
    }

    @Test
    void rejectsInvalidPatterns() {
        assertFalse(PermissionResolver.isValidPattern(""));
        assertFalse(PermissionResolver.isValidPattern(null));
        assertFalse(PermissionResolver.isValidPattern("users.*.create"));
        assertFalse(PermissionResolver.isValidPattern("users..create"));

        assertThrows(IllegalArgumentException.class, () -> PermissionResolver.matches("users..create", "users.create"));
    }
}
