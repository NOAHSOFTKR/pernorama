package pernorama.permission;

import java.util.Objects;

/**
 * Decides which {@linkplain PermissionGrant grants} apply when a
 * permission is checked in a context, and in what order. It is the only
 * place contexts are interpreted; {@link PermissionResolver} keeps
 * deciding between rules exactly as it always has, and never sees a
 * context.
 * <p>
 * The policy is chosen once, for a whole {@link pernorama.Pernorama}
 * instance — individual permissions do not carry their own. Both
 * policies treat a check <b>without</b> a context the same way: only
 * grants without a context apply. They differ in what a check
 * <b>with</b> a context sees.
 *
 * <h2>{@link #GLOBAL_FALLBACK}</h2>
 * A grant without a context is global: it applies in every context,
 * underneath the grants made for that context. Checking {@code node} in
 * {@code academy:123} goes through two layers:
 * <ol>
 *   <li>the grants scoped to {@code academy:123}. If any of their rules —
 *       allow or deny — covers {@code node}, they decide, with the usual
 *       precedence among themselves;</li>
 *   <li>only if none of them covers it, the grants without a context
 *       decide.</li>
 * </ol>
 * So a context overrides the global grants for every node it says
 * anything about, even with a less specific rule:
 *
 * <pre>{@code
 * students.delete               // global allow
 * -students.*   @ academy:123   // contextual deny
 *
 * students.delete @ academy:123 -> denied  (the context covers it)
 * students.delete @ academy:456 -> allowed (falls back to the global grant)
 * }</pre>
 *
 * and the reverse also holds: a context that grants {@code students.*}
 * permits {@code students.delete} there even if a global rule denies it.
 *
 * <h2>{@link #EXACT}</h2>
 * Grants with and without a context are separate. A check in
 * {@code academy:123} sees only the grants scoped to exactly
 * {@code academy:123}; a global grant does not reach into any context.
 *
 * <h2>Matching contexts</h2>
 * Two contexts match only if they are equal strings. No context value
 * has special meaning: {@code "academy:*"} is not a wildcard and
 * {@code "academy"} is not a parent of {@code "academy:123"}.
 */
public enum ContextPolicy {

    /**
     * Grants without a context apply in every context, underneath the
     * grants scoped to the context being checked; see the class
     * documentation for the precedence between the two.
     */
    GLOBAL_FALLBACK(true),

    /**
     * Only grants scoped to exactly the context being checked apply;
     * a grant without a context applies only to a check without one.
     */
    EXACT(false);

    private final boolean fallsBackToGlobal;

    ContextPolicy(boolean fallsBackToGlobal) {
        this.fallsBackToGlobal = fallsBackToGlobal;
    }

    /**
     * Returns {@code true} if something granted in {@code grantedContext}
     * applies to a check in {@code requestedContext} — whether it can
     * take part in the decision at all, not whether it wins it. Used to
     * decide which held roles count for a check; see
     * {@link #permits(Iterable, String, String)} for evaluating rules.
     *
     * @throws IllegalArgumentException if either context is empty
     */
    public boolean applies(String grantedContext, String requestedContext) {
        PermissionGrant.requireValidContext(grantedContext);
        PermissionGrant.requireValidContext(requestedContext);
        return Objects.equals(grantedContext, requestedContext) || fallsBackTo(grantedContext);
    }

    /**
     * Returns {@code true} if {@code grants} permit {@code node} in
     * {@code context} ({@code null} for a check without one), applying
     * this policy to pick the grants that apply and
     * {@link PermissionResolver}'s precedence among their rules. A node
     * no applicable rule covers is not permitted.
     * <p>
     * This is what {@link pernorama.subject.MemoryPermissionSubject}
     * calls, and what a custom subject storing grants with contexts
     * should call too.
     *
     * @throws pernorama.exception.InvalidPermissionException if {@code node} is not a
     *         syntactically valid permission node
     * @throws IllegalArgumentException if {@code context} is empty
     */
    public boolean permits(Iterable<PermissionGrant> grants, String node, String context) {
        Objects.requireNonNull(grants, "grants");
        PermissionGrant.requireValidContext(context);
        PermissionResolver.validateNode(node);

        // One pass, ranking the scoped and the global layer side by side.
        // A PermissionGrant validated its rule when it was created.
        int scoped = PermissionResolver.NOT_COVERING;
        int global = PermissionResolver.NOT_COVERING;
        for (PermissionGrant grant : grants) {
            Objects.requireNonNull(grant, "grant");
            if (Objects.equals(grant.context(), context)) {
                scoped = Math.max(scoped, PermissionResolver.rank(grant.rule(), node));
            } else if (fallsBackTo(grant.context())) {
                global = Math.max(global, PermissionResolver.rank(grant.rule(), node));
            }
        }

        PermissionResolver.Decision decision = PermissionResolver.decision(scoped);
        if (decision == PermissionResolver.Decision.NOT_COVERED) {
            decision = PermissionResolver.decision(global);
        }
        return decision == PermissionResolver.Decision.PERMITTED;
    }

    /**
     * Whether something granted in {@code grantedContext} reaches a check
     * in a different context: only a global grant does, and only under a
     * policy that falls back to global grants.
     */
    private boolean fallsBackTo(String grantedContext) {
        return fallsBackToGlobal && grantedContext == null;
    }
}
