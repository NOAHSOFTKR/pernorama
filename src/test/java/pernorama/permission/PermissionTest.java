package pernorama.permission;

import org.junit.jupiter.api.Test;
import pernorama.exception.PermissionDeniedException;
import pernorama.subject.MemoryPermissionSubject;

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
}
