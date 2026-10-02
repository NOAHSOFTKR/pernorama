package pernorama.permission;

import org.junit.jupiter.api.Test;
import pernorama.exception.PermissionDeniedException;
import pernorama.subject.MemoryPermissionSubject;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionTest {

    @Test
    void checkReturnsTrueWhenSubjectHasPermission() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("users.create");

        assertTrue(Permission.check(subject, "users.create"));
        assertFalse(Permission.check(subject, "users.delete"));
    }

    @Test
    void requireReturnsNormallyWhenSubjectHasPermission() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("users.create");

        Permission.require(subject, "users.create");
    }

    @Test
    void requireThrowsWhenSubjectLacksPermission() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();

        PermissionDeniedException exception = assertThrows(PermissionDeniedException.class,
                () -> Permission.require(subject, "users.create"));

        assertEquals("users.create", exception.requiredPermission());
        assertSame(subject, exception.subject());
    }

    @Test
    void checkAndRequireRejectNullSubject() {
        assertThrows(NullPointerException.class, () -> Permission.check(null, "users.create"));
        assertThrows(NullPointerException.class, () -> Permission.require(null, "users.create"));
    }

    @Test
    void checkAndRequireTakeAContext() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject(ContextPolicy.EXACT);
        subject.grant("students.edit", "academy:123");

        assertTrue(Permission.check(subject, "students.edit", "academy:123"));
        assertFalse(Permission.check(subject, "students.edit", "academy:456"));
        assertFalse(Permission.check(subject, "students.edit"));
        Permission.require(subject, "students.edit", "academy:123");
    }

    @Test
    void aDenialInAContextReportsTheContext() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();

        PermissionDeniedException exception = assertThrows(PermissionDeniedException.class,
                () -> Permission.require(subject, "students.edit", "academy:123"));

        assertEquals("students.edit", exception.requiredPermission());
        assertEquals(Optional.of("academy:123"), exception.context());
        assertEquals("Permission denied: students.edit in context academy:123", exception.getMessage());
    }

    @Test
    void aDenialWithoutAContextHasNone() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();

        PermissionDeniedException exception = assertThrows(PermissionDeniedException.class,
                () -> Permission.require(subject, "users.create"));

        assertEquals(Optional.empty(), exception.context());
        assertEquals("Permission denied: users.create", exception.getMessage());
    }
}
