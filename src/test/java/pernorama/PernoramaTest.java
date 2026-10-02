package pernorama;

import org.junit.jupiter.api.Test;
import pernorama.permission.ContextPolicy;
import pernorama.role.MemoryRoleAssignmentStore;
import pernorama.role.Role;
import pernorama.role.RoleAssignments;
import pernorama.subject.MemoryPermissionSubject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PernoramaTest {

    @Test
    void defaultsToGlobalFallback() {
        assertEquals(ContextPolicy.GLOBAL_FALLBACK, Pernorama.builder().build().contextPolicy());
    }

    @Test
    void subjectsUseTheConfiguredPolicy() {
        Pernorama exact = Pernorama.builder().contextPolicy(ContextPolicy.EXACT).build();
        Pernorama fallback = Pernorama.builder().contextPolicy(ContextPolicy.GLOBAL_FALLBACK).build();

        MemoryPermissionSubject strict = exact.newSubject();
        MemoryPermissionSubject loose = fallback.newSubject();
        strict.grant("students.read");
        loose.grant("students.read");

        assertEquals(ContextPolicy.EXACT, strict.contextPolicy());
        assertFalse(strict.hasPermission("students.read", "academy:123"));
        assertTrue(loose.hasPermission("students.read", "academy:123"));
        assertNotSame(exact.newSubject(), exact.newSubject());
    }

    @Test
    void roleAssignmentsUseTheConfiguredPolicy() {
        Pernorama exact = Pernorama.builder().contextPolicy(ContextPolicy.EXACT).build();
        Role reader = Role.builder("reader").permission("students.read").build();

        RoleAssignments<String> inMemory = exact.newRoleAssignments();
        RoleAssignments<String> inStore = exact.newRoleAssignments(new MemoryRoleAssignmentStore<>());
        inMemory.assign("alice", reader);

        assertEquals(ContextPolicy.EXACT, inMemory.contextPolicy());
        assertEquals(ContextPolicy.EXACT, inStore.contextPolicy());
        assertTrue(inMemory.subject("alice").hasPermission("students.read"));
        assertFalse(inMemory.subject("alice").hasPermission("students.read", "academy:123"));
    }

    @Test
    void rejectsANullPolicy() {
        assertThrows(NullPointerException.class, () -> Pernorama.builder().contextPolicy(null));
        assertThrows(NullPointerException.class, () -> new MemoryPermissionSubject((ContextPolicy) null));
    }
}
