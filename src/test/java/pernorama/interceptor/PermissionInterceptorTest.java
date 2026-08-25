package pernorama.interceptor;

import org.junit.jupiter.api.Test;
import pernorama.exception.PermissionDeniedException;
import pernorama.fixture.UserService;
import pernorama.subject.MemoryPermissionSubject;

import java.lang.reflect.Method;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionInterceptorTest {

    private final PermissionInterceptor interceptor = new PermissionInterceptor();

    @Test
    void allowsInvocationWhenSubjectHasPermission() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("users.create");
        UserService userService = new UserService();

        interceptor.invoke(subject, userService, "createUser");

        assertTrue(userService.isCreated());
    }

    @Test
    void blocksInvocationWhenSubjectLacksPermission() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        UserService userService = new UserService();

        assertThrows(PermissionDeniedException.class,
                () -> interceptor.invoke(subject, userService, "createUser"));
        assertFalse(userService.isCreated());
    }

    @Test
    void exceptionCarriesRequiredPermissionAndSubject() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        UserService userService = new UserService();

        PermissionDeniedException exception = assertThrows(PermissionDeniedException.class,
                () -> interceptor.invoke(subject, userService, "createUser"));

        assertEquals("users.create", exception.requiredPermission());
        assertSame(subject, exception.subject());
        assertEquals("Permission denied: users.create", exception.getMessage());
    }

    @Test
    void methodsWithoutPermAnnotationAreAlwaysAllowed() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        UserService userService = new UserService();

        interceptor.invoke(subject, userService, "ping");

        assertTrue(userService.isPinged());
    }

    @Test
    void invokeAcceptsAResolvedMethodDirectly() throws NoSuchMethodException {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        subject.grant("users.create");
        UserService userService = new UserService();
        Method method = UserService.class.getMethod("createUser");

        interceptor.invoke(subject, userService, method);

        assertTrue(userService.isCreated());
    }

    @Test
    void isPermittedReflectsSubjectPermissions() throws NoSuchMethodException {
        Method method = UserService.class.getMethod("createUser");
        MemoryPermissionSubject granted = new MemoryPermissionSubject();
        granted.grant("users.create");
        MemoryPermissionSubject denied = new MemoryPermissionSubject();

        assertTrue(interceptor.isPermitted(granted, method));
        assertFalse(interceptor.isPermitted(denied, method));
    }

    @Test
    void invokeThrowsWhenMethodDoesNotExist() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();
        UserService userService = new UserService();

        assertThrows(NoSuchElementException.class,
                () -> interceptor.invoke(subject, userService, "doesNotExist"));
    }
}
