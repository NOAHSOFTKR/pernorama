package pernorama.exception;

import org.junit.jupiter.api.Test;
import pernorama.subject.MemoryPermissionSubject;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ExceptionHierarchyTest {

    @Test
    void permissionDeniedExceptionIsAPernoramaException() {
        MemoryPermissionSubject subject = new MemoryPermissionSubject();

        PermissionDeniedException exception = new PermissionDeniedException("users.create", subject);

        assertTrue(exception instanceof PernoramaException);
        assertTrue(exception instanceof RuntimeException);
    }

    @Test
    void invalidPermissionExceptionIsAPernoramaException() {
        InvalidPermissionException exception = new InvalidPermissionException("users..create");

        assertTrue(exception instanceof PernoramaException);
        assertTrue(exception instanceof RuntimeException);
    }
}
