package pernorama.annotation;

import org.junit.jupiter.api.Test;
import pernorama.fixture.BaseDocumentService;
import pernorama.fixture.InheritedDocumentService;
import pernorama.fixture.OuterService;
import pernorama.fixture.OverridingDocumentService;
import pernorama.fixture.OverridingPingableService;
import pernorama.fixture.Pingable;
import pernorama.fixture.PingableService;
import pernorama.fixture.RedeclaringDocumentService;
import pernorama.fixture.UserService;

import java.lang.reflect.Method;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionAnnotationResolverTest {

    @Test
    void methodLevelPermWithoutGroupIsUsedAsIs() throws NoSuchMethodException {
        Method method = UserService.class.getMethod("createUser");

        assertEquals(Optional.of("users.create"), PermissionAnnotationResolver.resolve(method));
    }

    @Test
    void methodWithoutPermResolvesToEmpty() throws NoSuchMethodException {
        Method method = UserService.class.getMethod("ping");

        assertEquals(Optional.empty(), PermissionAnnotationResolver.resolve(method));
    }

    @Test
    void methodLevelPermIsPrefixedByClassLevelPermGroup() throws NoSuchMethodException {
        Method method = BaseDocumentService.class.getMethod("read");

        assertEquals(Optional.of("docs.read"), PermissionAnnotationResolver.resolve(method));
    }

    @Test
    void inheritedMethodNotOverriddenResolvesAgainstItsDeclaringSuperclass() throws NoSuchMethodException {
        Method method = InheritedDocumentService.class.getMethod("read");

        assertEquals(BaseDocumentService.class, method.getDeclaringClass());
        assertEquals(Optional.of("docs.read"), PermissionAnnotationResolver.resolve(method));
    }

    @Test
    void overriddenMethodWithoutRedeclaredPermRequiresNoPermission() throws NoSuchMethodException {
        Method method = OverridingDocumentService.class.getMethod("read");

        assertEquals(OverridingDocumentService.class, method.getDeclaringClass());
        assertEquals(Optional.empty(), PermissionAnnotationResolver.resolve(method));
    }

    @Test
    void overriddenMethodWithRedeclaredPermUsesItsOwnDeclaringClassGroup() throws NoSuchMethodException {
        Method method = RedeclaringDocumentService.class.getMethod("read");

        assertEquals(Optional.of("archive.readArchived"), PermissionAnnotationResolver.resolve(method));
    }

    @Test
    void unoverriddenInterfaceDefaultMethodResolvesAgainstTheInterface() throws NoSuchMethodException {
        Method method = PingableService.class.getMethod("ping");

        assertEquals(Pingable.class, method.getDeclaringClass());
        assertEquals(Optional.of("io.ping"), PermissionAnnotationResolver.resolve(method));
    }

    @Test
    void overriddenInterfaceMethodWithoutRedeclaredPermRequiresNoPermission() throws NoSuchMethodException {
        Method method = OverridingPingableService.class.getMethod("ping");

        assertEquals(Optional.empty(), PermissionAnnotationResolver.resolve(method));
    }

    @Test
    void nestedClassMethodResolvesLikeAnyOtherClass() throws NoSuchMethodException {
        Method method = OuterService.NestedService.class.getMethod("create");

        assertEquals(Optional.of("nested.create"), PermissionAnnotationResolver.resolve(method));
    }

    @Test
    void resolutionIsStableAcrossRepeatedCalls() throws NoSuchMethodException {
        Method method = BaseDocumentService.class.getMethod("read");

        Optional<String> first = PermissionAnnotationResolver.resolve(method);
        Optional<String> second = PermissionAnnotationResolver.resolve(method);

        assertEquals(first, second);
    }

    @Test
    void combineJoinsGroupAndValueWithADot() {
        assertEquals("users.create", PermissionAnnotationResolver.combine("users", "create"));
        assertEquals("create", PermissionAnnotationResolver.combine(null, "create"));
        assertEquals("create", PermissionAnnotationResolver.combine("", "create"));
        assertEquals("create", PermissionAnnotationResolver.combine("   ", "create"));
    }

    @Test
    void resolveRejectsNullMethod() {
        assertThrows(NullPointerException.class, () -> PermissionAnnotationResolver.resolve(null));
    }
}
