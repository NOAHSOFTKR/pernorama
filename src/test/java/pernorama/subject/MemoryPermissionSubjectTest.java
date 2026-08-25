package pernorama.subject;

import org.junit.jupiter.api.Test;
import pernorama.permission.PermissionNode;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MemoryPermissionSubjectTest {

    @Test
    void grantAllowsExactPermission() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();

        subject.grant("users.create");

        assertTrue(subject.hasPermission("users.create"));
        assertFalse(subject.hasPermission("users.delete"));
    }

    @Test
    void hasPermissionAcceptsPermissionNodeToo() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("users.create");

        assertTrue(subject.hasPermission(PermissionNode.of("users.create")));
        assertFalse(subject.hasPermission(PermissionNode.of("users.delete")));
    }

    @Test
    void revokeRemovesAnExactlyGrantedPermission() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("users.create");

        subject.revoke("users.create");

        assertFalse(subject.hasPermission("users.create"));
    }

    @Test
    void revokeOnlyRemovesExactMatchNotWildcardChildren() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("users.*");

        subject.revoke("users.create");

        assertTrue(subject.hasPermission("users.create"));

        subject.revoke("users.*");

        assertFalse(subject.hasPermission("users.create"));
    }

    @Test
    void globalWildcardGrantsEverything() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("*");

        assertTrue(subject.hasPermission("users.create"));
        assertTrue(subject.hasPermission("posts.delete"));
    }

    @Test
    void groupWildcardGrantsOnlyItsOwnGroup() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("users.*");

        assertTrue(subject.hasPermission("users.create"));
        assertTrue(subject.hasPermission("users.delete"));
        assertTrue(subject.hasPermission("users.update"));
        assertFalse(subject.hasPermission("posts.create"));
    }

    @Test
    void constructorAcceptsInitialPermissions() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject(List.of("users.create", "posts.read"));

        assertTrue(subject.hasPermission("users.create"));
        assertTrue(subject.hasPermission("posts.read"));
        assertEquals(Set.of("users.create", "posts.read"), subject.grantedPermissions());
    }

    @Test
    void grantedPermissionsViewIsUnmodifiable() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("users.create");

        assertThrows(UnsupportedOperationException.class, () -> subject.grantedPermissions().add("users.delete"));
    }

    @Test
    void grantRejectsInvalidPattern() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();

        assertThrows(IllegalArgumentException.class, () -> subject.grant("users..create"));
    }
}
