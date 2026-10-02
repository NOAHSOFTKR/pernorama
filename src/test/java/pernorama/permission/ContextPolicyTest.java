package pernorama.permission;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import pernorama.exception.InvalidPermissionException;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContextPolicyTest {

    private static final String A123 = "academy:123";
    private static final String A456 = "academy:456";

    /** Grants written as "rule" or "rule @ context". */
    private static List<PermissionGrant> grants(String... specs) {
        List<PermissionGrant> grants = new ArrayList<>();
        for (String spec : specs) {
            int at = spec.indexOf(" @ ");
            grants.add(at < 0
                    ? new PermissionGrant(spec, null)
                    : new PermissionGrant(spec.substring(0, at), spec.substring(at + 3)));
        }
        return grants;
    }

    // --- both policies ------------------------------------------------------

    @ParameterizedTest
    @EnumSource(ContextPolicy.class)
    void aCheckWithoutAContextSeesOnlyGrantsWithoutOne(ContextPolicy policy) {
        List<PermissionGrant> grants = grants("students.read", "students.edit @ " + A123);

        assertTrue(policy.permits(grants, "students.read", null));
        assertFalse(policy.permits(grants, "students.edit", null));
    }

    @ParameterizedTest
    @EnumSource(ContextPolicy.class)
    void aContextualGrantAppliesOnlyInItsOwnContext(ContextPolicy policy) {
        List<PermissionGrant> grants = grants("students.edit @ " + A123);

        assertTrue(policy.permits(grants, "students.edit", A123));
        assertFalse(policy.permits(grants, "students.edit", A456));
        assertFalse(policy.permits(grants, "students.edit", null));
    }

    @ParameterizedTest
    @EnumSource(ContextPolicy.class)
    void contextsAreComparedAsPlainStrings(ContextPolicy policy) {
        List<PermissionGrant> grants = grants(
                "a.read @ academy:*", "b.read @ academy", "c.read @ Academy:123", "d.read @ academy:123 ");

        assertFalse(policy.permits(grants, "a.read", A123)); // not a wildcard
        assertFalse(policy.permits(grants, "b.read", A123)); // not a parent
        assertFalse(policy.permits(grants, "c.read", A123)); // case-sensitive
        assertFalse(policy.permits(grants, "d.read", A123)); // whitespace is not trimmed
        assertTrue(policy.permits(grants, "a.read", "academy:*"));
    }

    @ParameterizedTest
    @EnumSource(ContextPolicy.class)
    void precedenceWithinOneContextIsUnchanged(ContextPolicy policy) {
        List<PermissionGrant> grants = grants(
                "* @ " + A123, "-users.* @ " + A123, "users.read @ " + A123);

        assertTrue(policy.permits(grants, "posts.read", A123));
        assertFalse(policy.permits(grants, "users.create", A123));
        assertTrue(policy.permits(grants, "users.read", A123));
    }

    @ParameterizedTest
    @EnumSource(ContextPolicy.class)
    void aDenyAndAnAllowOfEqualSpecificityInOneContextDeny(ContextPolicy policy) {
        List<PermissionGrant> grants = grants("users.delete @ " + A123, "-users.delete @ " + A123);

        assertFalse(policy.permits(grants, "users.delete", A123));
    }

    @ParameterizedTest
    @EnumSource(ContextPolicy.class)
    void nothingIsPermittedByDefault(ContextPolicy policy) {
        assertFalse(policy.permits(List.of(), "users.read", null));
        assertFalse(policy.permits(List.of(), "users.read", A123));
    }

    @ParameterizedTest
    @EnumSource(ContextPolicy.class)
    void invalidArgumentsAreRejected(ContextPolicy policy) {
        List<PermissionGrant> grants = grants("users.*");

        assertThrows(InvalidPermissionException.class, () -> policy.permits(grants, "users.*", A123));
        assertThrows(InvalidPermissionException.class, () -> policy.permits(grants, "-users.read", null));
        assertThrows(IllegalArgumentException.class, () -> policy.permits(grants, "users.read", ""));
        assertThrows(NullPointerException.class, () -> policy.permits(null, "users.read", null));
        assertThrows(IllegalArgumentException.class, () -> policy.applies("", null));
        assertThrows(IllegalArgumentException.class, () -> policy.applies(null, ""));
    }

    // --- GLOBAL_FALLBACK ----------------------------------------------------

    @Test
    void globalFallbackAppliesAGlobalGrantInEveryContext() {
        List<PermissionGrant> grants = grants("students.read");

        assertTrue(ContextPolicy.GLOBAL_FALLBACK.permits(grants, "students.read", null));
        assertTrue(ContextPolicy.GLOBAL_FALLBACK.permits(grants, "students.read", A123));
        assertTrue(ContextPolicy.GLOBAL_FALLBACK.permits(grants, "students.read", A456));
    }

    @Test
    void globalFallbackLetsAContextualDenyNarrowAGlobalWildcard() {
        List<PermissionGrant> grants = grants("students.*", "-students.delete @ " + A123);

        assertFalse(ContextPolicy.GLOBAL_FALLBACK.permits(grants, "students.delete", A123));
        assertTrue(ContextPolicy.GLOBAL_FALLBACK.permits(grants, "students.delete", A456));
        assertTrue(ContextPolicy.GLOBAL_FALLBACK.permits(grants, "students.read", A123));
        assertTrue(ContextPolicy.GLOBAL_FALLBACK.permits(grants, "students.delete", null));
    }

    @Test
    void globalFallbackLetsTheContextDecideEvenWithALessSpecificRule() {
        // the contextual wildcard covers the node, so the global exact rule is never consulted
        List<PermissionGrant> deniedHere = grants("students.delete", "-students.* @ " + A123);
        List<PermissionGrant> allowedHere = grants("-students.delete", "students.* @ " + A123);

        assertFalse(ContextPolicy.GLOBAL_FALLBACK.permits(deniedHere, "students.delete", A123));
        assertTrue(ContextPolicy.GLOBAL_FALLBACK.permits(deniedHere, "students.delete", A456));

        assertTrue(ContextPolicy.GLOBAL_FALLBACK.permits(allowedHere, "students.delete", A123));
        assertFalse(ContextPolicy.GLOBAL_FALLBACK.permits(allowedHere, "students.delete", A456));
    }

    @Test
    void globalFallbackFallsBackForNodesTheContextDoesNotCover() {
        List<PermissionGrant> grants = grants("*", "-students.* @ " + A123);

        assertFalse(ContextPolicy.GLOBAL_FALLBACK.permits(grants, "students.read", A123));
        assertTrue(ContextPolicy.GLOBAL_FALLBACK.permits(grants, "posts.read", A123));
    }

    @Test
    void globalFallbackDoesNotMixRulesAcrossTheTwoLayers() {
        // the context's deny covers the node; the global exact allow does not get a say
        List<PermissionGrant> grants = grants("users.read", "-* @ " + A123);

        assertFalse(ContextPolicy.GLOBAL_FALLBACK.permits(grants, "users.read", A123));
    }

    @Test
    void globalFallbackNeverAppliesOtherContexts() {
        List<PermissionGrant> grants = grants("students.* @ " + A456);

        assertFalse(ContextPolicy.GLOBAL_FALLBACK.permits(grants, "students.read", A123));
    }

    @Test
    void globalFallbackApplies() {
        assertTrue(ContextPolicy.GLOBAL_FALLBACK.applies(null, null));
        assertTrue(ContextPolicy.GLOBAL_FALLBACK.applies(null, A123));
        assertTrue(ContextPolicy.GLOBAL_FALLBACK.applies(A123, A123));
        assertFalse(ContextPolicy.GLOBAL_FALLBACK.applies(A123, null));
        assertFalse(ContextPolicy.GLOBAL_FALLBACK.applies(A123, A456));
    }

    // --- EXACT --------------------------------------------------------------

    @Test
    void exactKeepsGrantsWithAndWithoutAContextSeparate() {
        List<PermissionGrant> grants = grants("students.read");

        assertTrue(ContextPolicy.EXACT.permits(grants, "students.read", null));
        assertFalse(ContextPolicy.EXACT.permits(grants, "students.read", A123));

        grants.add(new PermissionGrant("students.read", A123));

        assertTrue(ContextPolicy.EXACT.permits(grants, "students.read", A123));
        assertFalse(ContextPolicy.EXACT.permits(grants, "students.read", A456));
    }

    @Test
    void exactIgnoresAGlobalDenyInsideAContext() {
        List<PermissionGrant> grants = grants("-*", "students.read @ " + A123);

        assertTrue(ContextPolicy.EXACT.permits(grants, "students.read", A123));
        assertFalse(ContextPolicy.EXACT.permits(grants, "students.read", null));
    }

    @Test
    void exactApplies() {
        assertTrue(ContextPolicy.EXACT.applies(null, null));
        assertFalse(ContextPolicy.EXACT.applies(null, A123));
        assertTrue(ContextPolicy.EXACT.applies(A123, A123));
        assertFalse(ContextPolicy.EXACT.applies(A123, null));
        assertFalse(ContextPolicy.EXACT.applies(A123, A456));
    }

    @Test
    void globalFallbackFallsBackToAGlobalDenyWhenTheContextSaysNothingAboutTheNode() {
        List<PermissionGrant> grants = grants("users.*", "-users.delete", "posts.read @ " + A123);

        assertFalse(ContextPolicy.GLOBAL_FALLBACK.permits(grants, "users.delete", A123));
        assertTrue(ContextPolicy.GLOBAL_FALLBACK.permits(grants, "users.read", A123));
        assertTrue(ContextPolicy.GLOBAL_FALLBACK.permits(grants, "posts.read", A123));
    }

    @Test
    void exactKeepsAContextualDenyOutOfAGlobalCheck() {
        List<PermissionGrant> grants = grants("users.read", "-* @ " + A123);

        assertTrue(ContextPolicy.EXACT.permits(grants, "users.read", null));
        assertFalse(ContextPolicy.EXACT.permits(grants, "users.read", A123));
        assertTrue(ContextPolicy.GLOBAL_FALLBACK.permits(grants, "users.read", null));
    }
}
