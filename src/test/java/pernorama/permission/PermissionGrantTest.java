package pernorama.permission;

import org.junit.jupiter.api.Test;
import pernorama.exception.InvalidPermissionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionGrantTest {

    @Test
    void acceptsAnyRuleWithOrWithoutAContext() {
        assertEquals("users.*", new PermissionGrant("users.*", null).rule());
        assertEquals("academy:123", new PermissionGrant("-users.delete", "academy:123").context());
        assertTrue(new PermissionGrant("*", "x").hasContext());
        assertFalse(new PermissionGrant("*", null).hasContext());
    }

    @Test
    void rejectsAnInvalidRule() {
        assertThrows(InvalidPermissionException.class, () -> new PermissionGrant("users..read", null));
        assertThrows(InvalidPermissionException.class, () -> new PermissionGrant(null, "academy:123"));
    }

    @Test
    void noContextHasExactlyOneSpelling() {
        assertThrows(IllegalArgumentException.class, () -> new PermissionGrant("users.read", ""));
        assertTrue(PermissionGrant.isValidContext(null));
        assertFalse(PermissionGrant.isValidContext(""));
        // anything else is opaque and accepted as-is
        assertTrue(PermissionGrant.isValidContext(" "));
        assertTrue(PermissionGrant.isValidContext("academy:*"));
        assertTrue(PermissionGrant.isValidContext("role == ADMIN"));
    }

    @Test
    void equalityIsRuleAndContext() {
        assertEquals(new PermissionGrant("users.read", "a"), new PermissionGrant("users.read", "a"));
        assertNotEquals(new PermissionGrant("users.read", "a"), new PermissionGrant("users.read", "b"));
        assertNotEquals(new PermissionGrant("users.read", "a"), new PermissionGrant("users.read", null));
    }

    @Test
    void toStringShowsTheContext() {
        assertEquals("users.read", new PermissionGrant("users.read", null).toString());
        assertEquals("users.read @ academy:123", new PermissionGrant("users.read", "academy:123").toString());
    }
}
