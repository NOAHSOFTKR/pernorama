package pernorama.role;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RoleGroupTest {

    @Test
    void defaultsAreUnboundedAndReject() {
        RoleGroup group = RoleGroup.builder("g").build();

        assertEquals("g", group.id());
        assertEquals(0, group.minAssignments());
        assertEquals(Integer.MAX_VALUE, group.maxAssignments());
        assertSame(RoleAssignmentPolicy.REJECT, group.assignmentPolicy());
    }

    @Test
    void keepsWhatItWasBuiltWith() {
        RoleGroup group = RoleGroup.builder("plan")
                .minAssignments(1)
                .maxAssignments(3)
                .assignmentPolicy(RoleAssignmentPolicy.REPLACE_OLDEST)
                .build();

        assertEquals(1, group.minAssignments());
        assertEquals(3, group.maxAssignments());
        assertSame(RoleAssignmentPolicy.REPLACE_OLDEST, group.assignmentPolicy());
    }

    @Test
    void invalidCardinalityIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> RoleGroup.builder("g").minAssignments(-1).build());
        assertThrows(IllegalArgumentException.class, () -> RoleGroup.builder("g").maxAssignments(0).build());
        assertThrows(IllegalArgumentException.class,
                () -> RoleGroup.builder("g").minAssignments(2).maxAssignments(1).build());
    }

    @Test
    void nullPolicyAndBlankIdAreRejected() {
        assertThrows(NullPointerException.class, () -> RoleGroup.builder("g").assignmentPolicy(null));
        assertThrows(IllegalArgumentException.class, () -> RoleGroup.builder(""));
    }

    @Test
    void identityIsTheId() {
        RoleGroup a = RoleGroup.builder("plan").maxAssignments(1).build();
        RoleGroup b = RoleGroup.builder("plan").maxAssignments(2).build();

        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, RoleGroup.builder("other").build());
    }
}
