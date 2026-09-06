package pernorama.subject;

import org.junit.jupiter.api.Test;
import pernorama.exception.InvalidPermissionException;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CompositePermissionSubjectTest {

    @Test
    void permissionFromAnySourceIsEnough() {
        PermissionSubject own = new MemoryPermissionSubject(List.of("profile.edit"));
        PermissionSubject admins = new MemoryPermissionSubject(List.of("users.*"));

        PermissionSubject user = new CompositePermissionSubject(own, admins);

        assertTrue(user.hasPermission("profile.edit"));
        assertTrue(user.hasPermission("users.create"));
        assertFalse(user.hasPermission("posts.delete"));
    }

    @Test
    void collectionAndVarargsConstructorsAgree() {
        PermissionSubject role = new MemoryPermissionSubject(List.of("users.read"));

        assertTrue(new CompositePermissionSubject(role).hasPermission("users.read"));
        assertTrue(new CompositePermissionSubject(List.of(role)).hasPermission("users.read"));
    }

    @Test
    void aCompositeWithNoSourcesPermitsNothing() {
        PermissionSubject user = new CompositePermissionSubject();

        assertFalse(user.hasPermission("users.read"));
    }

    @Test
    void invalidNodeIsRejectedEvenWithNoSourceToAskFirst() {
        PermissionSubject user = new CompositePermissionSubject();

        assertThrows(InvalidPermissionException.class, () -> user.hasPermission("users..read"));
        assertThrows(InvalidPermissionException.class, () -> user.hasPermission("-users.read"));
    }

    @Test
    void aDenyRuleOnlyLimitsTheSourceHoldingIt() {
        PermissionSubject role = new MemoryPermissionSubject(List.of("users.*", "-users.delete"));
        PermissionSubject own = new MemoryPermissionSubject(List.of("users.delete"));

        assertFalse(new CompositePermissionSubject(role).hasPermission("users.delete"));
        assertTrue(new CompositePermissionSubject(role, own).hasPermission("users.delete"));
    }

    @Test
    void grantAndRevokeAreRejected() {
        PermissionSubject role = new MemoryPermissionSubject(List.of("users.read"));
        PermissionSubject user = new CompositePermissionSubject(role);

        assertThrows(UnsupportedOperationException.class, () -> user.grant("users.delete"));
        assertThrows(UnsupportedOperationException.class, () -> user.revoke("users.read"));
    }

    @Test
    void sourcesViewIsUnmodifiableAndKeepsItsOrder() {
        PermissionSubject first = new MemoryPermissionSubject();
        PermissionSubject second = new MemoryPermissionSubject();

        CompositePermissionSubject user = new CompositePermissionSubject(first, second);

        assertEquals(List.of(first, second), user.sources());
        assertThrows(UnsupportedOperationException.class, () -> user.sources().add(new MemoryPermissionSubject()));
    }

    @Test
    void changesToASourceAreVisibleThroughTheComposite() {
        MemoryPermissionSubject role = new MemoryPermissionSubject();
        PermissionSubject user = new CompositePermissionSubject(role);

        assertFalse(user.hasPermission("users.read"));

        role.grant("users.read");

        assertTrue(user.hasPermission("users.read"));
    }

    @Test
    void rejectsNullSources() {
        assertThrows(NullPointerException.class, () -> new CompositePermissionSubject((PermissionSubject) null));
        assertThrows(NullPointerException.class, () -> new CompositePermissionSubject((PermissionSubject[]) null));
    }
}
