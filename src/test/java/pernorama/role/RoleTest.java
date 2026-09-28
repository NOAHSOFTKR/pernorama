package pernorama.role;

import org.junit.jupiter.api.Test;
import pernorama.exception.InvalidPermissionException;
import pernorama.subject.MemoryPermissionSubject;
import pernorama.subject.PermissionSubject;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RoleTest {

    @Test
    void ruleBackedRoleUsesTheCoreMatchingRules() {
        Role moderator = Role.builder("moderator")
                .permission("users.*")
                .permission("-users.delete")
                .build();

        assertTrue(moderator.permissions().hasPermission("users.create"));
        assertFalse(moderator.permissions().hasPermission("users.delete"));
        assertFalse(moderator.permissions().hasPermission("posts.read"));
    }

    @Test
    void deniesIsTrueOnlyWhenADenyRuleDecides() {
        Role auditor = Role.builder("auditor")
                .permission("*")
                .permission("-users.*")
                .permission("users.read")
                .build();

        assertTrue(auditor.denies("users.create"));
        assertFalse(auditor.denies("users.read"));  // the exact allow wins
        assertFalse(auditor.denies("posts.read"));  // permitted by *

        Role reader = Role.builder("reader").permission("posts.read").build();
        assertFalse(reader.denies("users.delete")); // not covered at all: not a denial
    }

    @Test
    void invalidRuleIsRejectedAtBuildTime() {
        assertThrows(InvalidPermissionException.class, () -> Role.builder("r").permission("users..read"));
        assertThrows(InvalidPermissionException.class, () -> Role.builder("r").permission(null));
    }

    @Test
    void invalidNodeIsRejectedOnCheck() {
        Role ruleBacked = Role.builder("r").permission("*").build();
        Role subjectBacked = Role.builder("s").permissions(new MemoryPermissionSubject()).build();

        assertThrows(InvalidPermissionException.class, () -> ruleBacked.permissions().hasPermission("-users"));
        assertThrows(InvalidPermissionException.class, () -> ruleBacked.denies("users.*"));
        assertThrows(InvalidPermissionException.class, () -> subjectBacked.denies("users..read"));
    }

    @Test
    void ruleBackedPermissionsAreReadOnly() {
        Role role = Role.builder("r").permission("users.read").build();

        assertThrows(UnsupportedOperationException.class, () -> role.permissions().grant("users.delete"));
        assertThrows(UnsupportedOperationException.class, () -> role.permissions().revoke("users.read"));
    }

    @Test
    void subjectBackedRoleDelegatesAndNeverDenies() {
        PermissionSubject stored = new MemoryPermissionSubject(List.of("users.*", "-users.delete"));
        Role role = Role.builder("stored").permissions(stored).build();

        assertSame(stored, role.permissions());
        assertTrue(role.permissions().hasPermission("users.read"));
        assertFalse(role.permissions().hasPermission("users.delete"));
        assertFalse(role.denies("users.delete"));

        stored.revoke("users.*");
        assertFalse(role.permissions().hasPermission("users.read"));
    }

    @Test
    void rulesAndBackingSubjectCannotBeCombined() {
        Role.Builder builder = Role.builder("r")
                .permission("users.read")
                .permissions(new MemoryPermissionSubject());

        assertThrows(IllegalStateException.class, builder::build);
    }

    @Test
    void identityIsTheId() {
        RoleGroup group = RoleGroup.builder("g").build();
        Role a = Role.builder("admin").permission("*").build();
        Role b = Role.builder("admin").group(group).build();

        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, Role.builder("other").build());
        assertEquals("admin", a.toString());
    }

    @Test
    void groupIsOptional() {
        RoleGroup group = RoleGroup.builder("g").build();

        assertEquals(Optional.empty(), Role.builder("a").build().group());
        assertEquals(Optional.of(group), Role.builder("b").group(group).build().group());
    }

    @Test
    void blankIdIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> Role.builder(null));
        assertThrows(IllegalArgumentException.class, () -> Role.builder(" "));
        assertThrows(IllegalArgumentException.class, () -> Role.builder(" admin"));
    }

    @Test
    void emptyRoleCanBeBuiltAndPermitsNothing() {
        Role role = Role.builder("nobody").build();

        assertFalse(role.permissions().hasPermission("users.read"));
        assertFalse(role.denies("users.read"));
    }
}
