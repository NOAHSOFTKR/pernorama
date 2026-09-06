package pernorama.permission;

import org.junit.jupiter.api.Test;
import pernorama.exception.InvalidPermissionException;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionResolverTest {

    @Test
    void exactPatternMatchesOnlyItself() {
        assertTrue(PermissionResolver.matches("users.create", "users.create"));
        assertFalse(PermissionResolver.matches("users.create", "users.delete"));
    }

    @Test
    void globalWildcardMatchesAnything() {
        assertTrue(PermissionResolver.matches("*", "users.create"));
        assertTrue(PermissionResolver.matches("*", "posts.delete"));
        assertTrue(PermissionResolver.matches("*", "anything.at.all"));
    }

    @Test
    void groupWildcardMatchesItsChildren() {
        assertTrue(PermissionResolver.matches("users.*", "users.create"));
        assertTrue(PermissionResolver.matches("users.*", "users.delete"));
        assertTrue(PermissionResolver.matches("users.*", "users.update"));
        assertTrue(PermissionResolver.matches("users.*", "users.create.special"));
    }

    @Test
    void groupWildcardDoesNotMatchUnrelatedGroups() {
        assertFalse(PermissionResolver.matches("users.*", "posts.create"));
        assertFalse(PermissionResolver.matches("users.*", "userservice.create"));
    }

    @Test
    void matchesAnyChecksEveryPattern() {
        List<String> granted = List.of("posts.read", "users.*");

        assertTrue(PermissionResolver.matchesAny(granted, "users.create"));
        assertTrue(PermissionResolver.matchesAny(granted, "posts.read"));
        assertFalse(PermissionResolver.matchesAny(granted, "posts.delete"));
    }

    @Test
    void rejectsInvalidPatterns() {
        assertFalse(PermissionResolver.isValidPattern(""));
        assertFalse(PermissionResolver.isValidPattern(null));
        assertFalse(PermissionResolver.isValidPattern("users.*.create"));
        assertFalse(PermissionResolver.isValidPattern("users..create"));

        assertThrows(InvalidPermissionException.class, () -> PermissionResolver.matches("users..create", "users.create"));
    }

    @Test
    void denyRuleNeverAllowsAndAllowRuleNeverDenies() {
        assertFalse(PermissionResolver.matches("-users.delete", "users.delete"));
        assertTrue(PermissionResolver.denies("-users.delete", "users.delete"));

        assertTrue(PermissionResolver.matches("users.delete", "users.delete"));
        assertFalse(PermissionResolver.denies("users.delete", "users.delete"));
    }

    @Test
    void denyRuleCarvesANodeOutOfAWildcardGrant() {
        List<String> granted = List.of("users.*", "-users.delete");

        assertTrue(PermissionResolver.matchesAny(granted, "users.create"));
        assertTrue(PermissionResolver.matchesAny(granted, "users.profile.read"));
        assertFalse(PermissionResolver.matchesAny(granted, "users.delete"));
    }

    @Test
    void allowRuleCarvesANodeOutOfAWildcardDeny() {
        List<String> granted = List.of("*", "-users.*", "users.read");

        assertTrue(PermissionResolver.matchesAny(granted, "posts.create"));
        assertFalse(PermissionResolver.matchesAny(granted, "users.create"));
        assertTrue(PermissionResolver.matchesAny(granted, "users.read"));
    }

    @Test
    void longerWildcardPrefixWinsOverAShorterOne() {
        List<String> granted = List.of("-users.*", "users.profile.*");

        assertFalse(PermissionResolver.matchesAny(granted, "users.create"));
        assertTrue(PermissionResolver.matchesAny(granted, "users.profile.read"));
    }

    @Test
    void denyWinsWhenTwoRulesAreEquallySpecific() {
        assertFalse(PermissionResolver.matchesAny(List.of("users.delete", "-users.delete"), "users.delete"));
        assertFalse(PermissionResolver.matchesAny(List.of("-users.delete", "users.delete"), "users.delete"));
        assertFalse(PermissionResolver.matchesAny(List.of("*", "-*"), "anything.at.all"));
    }

    @Test
    void aNodeNoRuleCoversIsNotPermitted() {
        assertFalse(PermissionResolver.matchesAny(List.of("posts.*"), "users.read"));
        assertFalse(PermissionResolver.matchesAny(List.of(), "users.read"));
        assertFalse(PermissionResolver.matchesAny(List.of("-users.*"), "users.read"));
    }

    @Test
    void denyPrefixIsOnlyReadOnceAndOnlyAtTheStart() {
        assertTrue(PermissionResolver.isValidPattern("-users.delete"));
        assertTrue(PermissionResolver.isValidPattern("-users.*"));
        assertTrue(PermissionResolver.isValidPattern("-*"));
        assertTrue(PermissionResolver.isValidPattern("users.soft-delete"));

        assertFalse(PermissionResolver.isValidPattern("-"));
        assertFalse(PermissionResolver.isValidPattern("--users"));

        assertThrows(InvalidPermissionException.class, () -> PermissionResolver.denies("--users", "users"));
    }
    @Test
    void anExactDenyCoversItsOwnNodeOnlyNotTheSubtreeBelowIt() {
        List<String> exact = List.of("users.*", "-users.delete");

        assertFalse(PermissionResolver.matchesAny(exact, "users.delete"));
        assertTrue(PermissionResolver.matchesAny(exact, "users.delete.hard"));

        List<String> subtree = List.of("users.*", "-users.delete.*");

        assertFalse(PermissionResolver.matchesAny(subtree, "users.delete"));
        assertFalse(PermissionResolver.matchesAny(subtree, "users.delete.hard"));
    }

    @Test
    void anExactAllowBeatsADenyOnTheSubtreeBelowIt() {
        List<String> granted = List.of("users.delete", "-users.delete.*");

        assertTrue(PermissionResolver.matchesAny(granted, "users.delete"));
        assertFalse(PermissionResolver.matchesAny(granted, "users.delete.hard"));
    }

    @Test
    void aWildcardDenyCoversTheGroupNodeItself() {
        assertFalse(PermissionResolver.matchesAny(List.of("users.*", "-users.*"), "users"));
        assertTrue(PermissionResolver.denies("-users.*", "users"));
        assertTrue(PermissionResolver.denies("-*", "anything.at.all"));
    }

    @Test
    void theAnswerDoesNotDependOnRuleOrder() {
        assertFalse(PermissionResolver.matchesAny(List.of("users.*", "-users.*"), "users.create"));
        assertFalse(PermissionResolver.matchesAny(List.of("-users.*", "users.*"), "users.create"));

        assertTrue(PermissionResolver.matchesAny(List.of("-users.*", "users.profile.*"), "users.profile.read"));
        assertTrue(PermissionResolver.matchesAny(List.of("users.profile.*", "-users.*"), "users.profile.read"));

        assertTrue(PermissionResolver.matchesAny(List.of("*", "-users.*", "users.read"), "users.read"));
        assertTrue(PermissionResolver.matchesAny(List.of("users.read", "-users.*", "*"), "users.read"));
    }

    @Test
    void permissionNodeOverloadsAgreeWithTheStringForms() {
        PermissionNode node = PermissionNode.of("users.delete");

        assertTrue(PermissionResolver.denies("-users.delete", node));
        assertFalse(PermissionResolver.matches("-users.delete", node));
        assertTrue(PermissionResolver.matches("users.*", node));
        assertFalse(PermissionResolver.denies("users.*", node));
    }

    @Test
    void rejectsARequiredValueThatIsNotANode() {
        List<String> granted = List.of("*", "-users.*");

        assertThrows(InvalidPermissionException.class, () -> PermissionResolver.matchesAny(granted, "-users.read"));
        assertThrows(InvalidPermissionException.class, () -> PermissionResolver.matchesAny(granted, "users.*"));
        assertThrows(InvalidPermissionException.class, () -> PermissionResolver.matchesAny(granted, "users.delete."));
        assertThrows(InvalidPermissionException.class, () -> PermissionResolver.matchesAny(granted, null));
        assertThrows(InvalidPermissionException.class, () -> PermissionResolver.matches("*", "-users.read"));
        assertThrows(InvalidPermissionException.class, () -> PermissionResolver.denies("-*", "users.*"));
    }

    @Test
    void everyRuleIsValidatedEvenAfterOneAlreadyCoversTheNode() {
        assertThrows(InvalidPermissionException.class,
                () -> PermissionResolver.matchesAny(List.of("*", "users..bad"), "users.read"));
    }
}
