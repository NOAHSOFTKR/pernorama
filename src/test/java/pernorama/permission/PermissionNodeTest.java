package pernorama.permission;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionNodeTest {

    @Test
    void createsNodeFromDottedString() {
        PermissionNode node = PermissionNode.of("users.create");

        assertEquals("users.create", node.name());
        assertEquals(java.util.List.of("users", "create"), node.segments());
    }

    @Test
    void rejectsBlankOrMalformedInput() {
        assertThrows(IllegalArgumentException.class, () -> PermissionNode.of(""));
        assertThrows(IllegalArgumentException.class, () -> PermissionNode.of("   "));
        assertThrows(IllegalArgumentException.class, () -> PermissionNode.of(null));
        assertThrows(IllegalArgumentException.class, () -> PermissionNode.of("users..create"));
        assertThrows(IllegalArgumentException.class, () -> PermissionNode.of(".users"));
        assertThrows(IllegalArgumentException.class, () -> PermissionNode.of("users."));
        assertThrows(IllegalArgumentException.class, () -> PermissionNode.of("users.*"));
    }

    @Test
    void nodesWithSameNameAreEqual() {
        PermissionNode first = PermissionNode.of("users.create");
        PermissionNode second = PermissionNode.of("users.create");
        PermissionNode different = PermissionNode.of("users.delete");

        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
        assertFalse(first.equals(different));
    }

    @Test
    void parentIsOneSegmentShorter() {
        PermissionNode node = PermissionNode.of("users.create.special");

        assertTrue(node.parent().isPresent());
        assertEquals(PermissionNode.of("users.create"), node.parent().get());
        assertTrue(node.parent().get().parent().isPresent());
        assertEquals(PermissionNode.of("users"), node.parent().get().parent().get());
        assertTrue(node.parent().get().parent().get().parent().isEmpty());
    }

    @Test
    void isChildOfDescribesStrictDescendants() {
        PermissionNode root = PermissionNode.of("users");
        PermissionNode create = PermissionNode.of("users.create");
        PermissionNode special = PermissionNode.of("users.create.special");
        PermissionNode unrelated = PermissionNode.of("posts.create");

        assertTrue(create.isChildOf(root));
        assertTrue(special.isChildOf(create));
        assertTrue(special.isChildOf(root));
        assertFalse(root.isChildOf(root));
        assertFalse(create.isChildOf(create));
        assertFalse(root.isChildOf(create));
        assertFalse(create.isChildOf(unrelated));

        assertTrue(create.isChildOf("users"));
    }
}
