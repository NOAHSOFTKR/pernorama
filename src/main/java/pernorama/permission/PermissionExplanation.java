package pernorama.permission;

import pernorama.exception.InvalidPermissionException;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Why a permission check came out the way it did: what was checked, the
 * answer, and — as far as the answering subject can tell — the rules,
 * context layer and sources that decided it.
 *
 * <pre>{@code
 * PermissionExplanation explanation = user.explain("students.delete", "academy:123");
 *
 * explanation.allowed();       // false
 * explanation.decision();      // Optional[DENIED]
 * explanation.decidingLayer(); // Optional[EXACT_CONTEXT]
 * explanation.matches();       // [-students.* @ academy:123 (decisive), students.delete]
 * }</pre>
 *
 * Get one from {@link pernorama.subject.PermissionSubject#explain(String, String)}.
 * Its {@link #allowed()} is always the answer
 * {@link pernorama.subject.PermissionSubject#hasPermission(String, String) hasPermission}
 * gives for the same node and context; everything else describes how that
 * answer was reached.
 *
 * <h2>Decision</h2>
 * {@link #decision()} keeps apart what {@link #allowed()} folds together:
 * {@link PermissionResolver.Decision#DENIED} when a deny rule (or a denying
 * source) decided the node, and {@link PermissionResolver.Decision#NOT_COVERED}
 * when nothing covered it at all. Both mean {@code allowed() == false}. It is
 * empty when the subject only says "not allowed" without saying which — a
 * custom subject that does not override {@code explain}, for instance.
 *
 * <h2>Provenance</h2>
 * An explanation never reports a reason it could not determine.
 * {@link #provenance()} says how much of the reason is known:
 * {@link Provenance#COMPLETE} when every rule and source behind the answer
 * is reported, {@link Provenance#PARTIAL} when some of it is, and
 * {@link Provenance#UNAVAILABLE} when only the answer is.
 *
 * <h2>Rules and sources</h2>
 * A subject that holds grants itself, such as
 * {@link pernorama.subject.MemoryPermissionSubject}, reports in
 * {@link #matches()} every applicable grant whose rule covers the node, the
 * deciding ones marked {@linkplain RuleMatch#decisive() decisive}. A subject
 * that combines others, such as
 * {@link pernorama.subject.CompositePermissionSubject} or a role-assignment
 * subject, reports one {@link Contribution} per source instead, each with
 * the source's own explanation.
 *
 * <h2>Who may see one</h2>
 * An explanation is diagnostic information about how a subject's
 * permissions are configured — the grants, roles and contexts it holds.
 * Log it, or show it to administrators; do not hand it unfiltered to the
 * end user whose request was denied, which would tell them exactly what
 * they lack and where it is granted.
 * <p>
 * Immutable, except that a {@link Contribution#source()} is the live
 * subject or assignment that was consulted, not a copy of it.
 */
public final class PermissionExplanation {

    /**
     * Which grants (or role assignments) decided a check, when a
     * {@link ContextPolicy} put them in layers.
     */
    public enum Layer {
        /**
         * Those held in exactly the checked context — for a check without
         * a context, those held without one.
         */
        EXACT_CONTEXT,
        /**
         * Those held without a context, reached from a check in a context
         * because {@link ContextPolicy#GLOBAL_FALLBACK} falls back to them
         * when nothing held in the context covers the node.
         */
        GLOBAL_FALLBACK
    }

    /** How much of the reason for an answer an explanation reports. */
    public enum Provenance {
        /** The decision and every rule and source behind it are reported. */
        COMPLETE,
        /**
         * Part of the reason is reported — some source only gave its
         * answer, or the way sources were combined is not known.
         */
        PARTIAL,
        /** Only the answer is known; nothing about why. */
        UNAVAILABLE
    }

    /**
     * One applicable grant whose rule covers the checked node.
     *
     * @param grant    the grant, with the context it is held in
     * @param decisive whether this rule decided the answer: the most
     *                 specific covering rule of the deciding layer, a deny
     *                 rule winning a tie
     */
    public record RuleMatch(PermissionGrant grant, boolean decisive) {

        /**
         * @throws NullPointerException if {@code grant} is null
         */
        public RuleMatch {
            Objects.requireNonNull(grant, "grant");
        }

        /** Whether the rule is a deny rule. */
        public boolean deny() {
            return PermissionResolver.isDeny(grant.rule());
        }

        /** Whether the rule ends in a wildcard ({@code "users.*"}, {@code "*"}). */
        public boolean wildcard() {
            return grant.rule().endsWith("*");
        }

        @Override
        public String toString() {
            return decisive ? grant + " (decisive)" : grant.toString();
        }
    }

    /**
     * One source a combining subject consulted, with that source's own
     * explanation.
     *
     * @param source      what was consulted: the
     *                    {@link pernorama.subject.PermissionSubject} for a
     *                    composite, the {@code RoleAssignment} for a
     *                    role-assignment subject
     * @param decisive    whether this source's answer decided the combined
     *                    answer; {@code false} for every source when how
     *                    they were combined is not known
     * @param explanation the source's own explanation
     */
    public record Contribution(Object source, boolean decisive, PermissionExplanation explanation) {

        /**
         * @throws NullPointerException if {@code source} or
         *         {@code explanation} is null
         */
        public Contribution {
            Objects.requireNonNull(source, "source");
            Objects.requireNonNull(explanation, "explanation");
        }

        @Override
        public String toString() {
            return source + (decisive ? " (decisive)" : "") + ": " + explanation;
        }
    }

    private final String node;
    private final String context;
    private final boolean allowed;
    private final PermissionResolver.Decision decision;
    private final Provenance provenance;
    private final ContextPolicy contextPolicy;
    private final String resolutionPolicy;
    private final Layer decidingLayer;
    private final List<RuleMatch> matches;
    private final List<Contribution> contributions;

    private PermissionExplanation(Builder builder) {
        this.node = builder.node;
        this.context = builder.context;
        this.allowed = builder.allowed;
        this.decision = builder.allowed ? PermissionResolver.Decision.PERMITTED : builder.decision;
        this.provenance = builder.provenance;
        this.contextPolicy = builder.contextPolicy;
        this.resolutionPolicy = builder.resolutionPolicy;
        this.decidingLayer = builder.decidingLayer;
        this.matches = List.copyOf(builder.matches);
        this.contributions = List.copyOf(builder.contributions);
    }

    /**
     * An explanation that reports only the answer, with
     * {@link Provenance#UNAVAILABLE}: what
     * {@link pernorama.subject.PermissionSubject#explain(String, String)}
     * returns for a subject that does not override it.
     *
     * @throws InvalidPermissionException if {@code node} is not a valid
     *         permission node
     * @throws IllegalArgumentException if {@code context} is empty
     */
    public static PermissionExplanation unavailable(String node, String context, boolean allowed) {
        return builder(node, context, allowed).build();
    }

    /**
     * Starts building an explanation, for a custom subject or resolution
     * policy that can report more than its answer. Every property but the
     * answer is optional, and {@link #provenance()} defaults to
     * {@link Provenance#UNAVAILABLE}: report what you know, and claim
     * {@link Provenance#COMPLETE} only if it is everything.
     */
    public static Builder builder(String node, String context, boolean allowed) {
        return new Builder(node, context, allowed);
    }

    /**
     * The explanation of a set of rules, given every applicable grant that
     * covers {@code node} with its rank. {@code contextPolicy} is the
     * policy that put them in layers, or {@code null} for a plain rule set
     * with no contexts, which has no layers.
     */
    static PermissionExplanation ofRules(String node, String context, PermissionResolver.Decision decision,
                                         ContextPolicy contextPolicy, List<RankedGrant> covering) {
        // The scoped layer decides whenever it covers the node at all.
        boolean scopedCovers = false;
        int scopedBest = PermissionResolver.NOT_COVERING;
        int globalBest = PermissionResolver.NOT_COVERING;
        for (RankedGrant ranked : covering) {
            if (ranked.fallback()) {
                globalBest = Math.max(globalBest, ranked.rank());
            } else {
                scopedCovers = true;
                scopedBest = Math.max(scopedBest, ranked.rank());
            }
        }
        boolean decidingIsFallback = !scopedCovers;
        int decidingBest = scopedCovers ? scopedBest : globalBest;

        List<RankedGrant> ordered = new ArrayList<>(covering);
        ordered.sort(Comparator.comparing(RankedGrant::fallback)
                .thenComparing(Comparator.comparingInt(RankedGrant::rank).reversed()));

        Builder builder = builder(node, context, decision == PermissionResolver.Decision.PERMITTED)
                .decision(decision)
                .provenance(Provenance.COMPLETE)
                .contextPolicy(contextPolicy);
        if (contextPolicy != null && !covering.isEmpty()) {
            builder.decidingLayer(decidingIsFallback ? Layer.GLOBAL_FALLBACK : Layer.EXACT_CONTEXT);
        }
        for (RankedGrant ranked : ordered) {
            boolean decisive = ranked.fallback() == decidingIsFallback && ranked.rank() == decidingBest;
            builder.match(new RuleMatch(ranked.grant(), decisive));
        }
        return builder.build();
    }

    /** The node that was checked. */
    public String node() {
        return node;
    }

    /** The context the node was checked in, if any. */
    public Optional<String> context() {
        return Optional.ofNullable(context);
    }

    /**
     * The answer: what {@link pernorama.subject.PermissionSubject#hasPermission(String, String)}
     * returns for the same node and context.
     */
    public boolean allowed() {
        return allowed;
    }

    /**
     * {@link PermissionResolver.Decision#PERMITTED} if allowed; otherwise
     * {@link PermissionResolver.Decision#DENIED} or
     * {@link PermissionResolver.Decision#NOT_COVERED} if the subject can
     * tell which, and empty if it cannot.
     */
    public Optional<PermissionResolver.Decision> decision() {
        return Optional.ofNullable(decision);
    }

    /** How much of the reason for the answer this explanation reports. */
    public Provenance provenance() {
        return provenance;
    }

    /** The context policy that put grants or role assignments in layers, if one did. */
    public Optional<ContextPolicy> contextPolicy() {
        return Optional.ofNullable(contextPolicy);
    }

    /**
     * How {@link #contributions()} were combined, if that is known:
     * {@code "ANY_SOURCE"} for a {@link pernorama.subject.CompositePermissionSubject},
     * and {@code "ALLOW_OVERRIDES"} or {@code "DENY_OVERRIDES"} for a
     * role-assignment subject using that built-in policy. Empty for a
     * custom policy, and for a subject that does not combine sources.
     */
    public Optional<String> resolutionPolicy() {
        return Optional.ofNullable(resolutionPolicy);
    }

    /**
     * Which layer decided, when a {@link ContextPolicy} put grants or role
     * assignments in layers and one of them covered the node. Empty when
     * nothing covered it, and for a plain rule set, which has no layers.
     */
    public Optional<Layer> decidingLayer() {
        return Optional.ofNullable(decidingLayer);
    }

    /**
     * Every applicable grant whose rule covers the node, in precedence
     * order: the grants held in the checked context before those reached
     * by falling back to global grants, and within each, the more specific
     * rule — and on a tie, the deny rule — first. Grants that do not cover
     * the node, or that do not apply to the checked context, are left out.
     * Empty for a subject that does not hold grants itself.
     */
    public List<RuleMatch> matches() {
        return matches;
    }

    /**
     * The sources a combining subject consulted, in the order it holds
     * them, each with its own explanation. Empty for a subject that does
     * not combine sources.
     */
    public List<Contribution> contributions() {
        return contributions;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("PermissionExplanation[node=").append(node);
        if (context != null) {
            sb.append(", context=").append(context);
        }
        sb.append(", allowed=").append(allowed);
        if (decision != null) {
            sb.append(", decision=").append(decision);
        }
        sb.append(", provenance=").append(provenance);
        if (contextPolicy != null) {
            sb.append(", contextPolicy=").append(contextPolicy);
        }
        if (resolutionPolicy != null) {
            sb.append(", resolutionPolicy=").append(resolutionPolicy);
        }
        if (decidingLayer != null) {
            sb.append(", decidingLayer=").append(decidingLayer);
        }
        if (!matches.isEmpty()) {
            sb.append(", matches=").append(matches);
        }
        if (!contributions.isEmpty()) {
            sb.append(", contributions=").append(contributions);
        }
        return sb.append(']').toString();
    }

    /** Builder for {@link PermissionExplanation}. Not thread-safe. */
    public static final class Builder {

        private final String node;
        private final String context;
        private final boolean allowed;
        private PermissionResolver.Decision decision;
        private Provenance provenance = Provenance.UNAVAILABLE;
        private ContextPolicy contextPolicy;
        private String resolutionPolicy;
        private Layer decidingLayer;
        private final List<RuleMatch> matches = new ArrayList<>();
        private final List<Contribution> contributions = new ArrayList<>();

        private Builder(String node, String context, boolean allowed) {
            PermissionResolver.validateNode(node);
            PermissionGrant.requireValidContext(context);
            this.node = node;
            this.context = context;
            this.allowed = allowed;
        }

        /**
         * Sets the three-way decision. It has to agree with the answer:
         * {@link PermissionResolver.Decision#PERMITTED} exactly when allowed.
         * An allowed explanation is {@code PERMITTED} without calling this.
         *
         * @throws IllegalArgumentException if {@code decision} contradicts
         *         the answer
         */
        public Builder decision(PermissionResolver.Decision decision) {
            Objects.requireNonNull(decision, "decision");
            if ((decision == PermissionResolver.Decision.PERMITTED) != allowed) {
                throw new IllegalArgumentException(
                        "decision " + decision + " contradicts allowed=" + allowed);
            }
            this.decision = decision;
            return this;
        }

        /** Sets how much of the reason is reported. Defaults to {@link Provenance#UNAVAILABLE}. */
        public Builder provenance(Provenance provenance) {
            this.provenance = Objects.requireNonNull(provenance, "provenance");
            return this;
        }

        /** Sets the context policy that put grants or assignments in layers; {@code null} for none. */
        public Builder contextPolicy(ContextPolicy contextPolicy) {
            this.contextPolicy = contextPolicy;
            return this;
        }

        /** Names how the contributions were combined; {@code null} if not known. */
        public Builder resolutionPolicy(String resolutionPolicy) {
            this.resolutionPolicy = resolutionPolicy;
            return this;
        }

        /** Sets the layer that decided; {@code null} if none did. */
        public Builder decidingLayer(Layer decidingLayer) {
            this.decidingLayer = decidingLayer;
            return this;
        }

        /** Adds a covering rule, in precedence order. */
        public Builder match(RuleMatch match) {
            matches.add(Objects.requireNonNull(match, "match"));
            return this;
        }

        /** Adds a consulted source, in the order the subject holds them. */
        public Builder contribution(Contribution contribution) {
            contributions.add(Objects.requireNonNull(contribution, "contribution"));
            return this;
        }

        /**
         * Builds the explanation.
         *
         * @throws IllegalStateException if the provenance is
         *         {@link Provenance#COMPLETE} but a denied answer has no
         *         {@linkplain #decision decision}: a complete explanation
         *         knows whether the node was denied or not covered
         */
        public PermissionExplanation build() {
            if (provenance == Provenance.COMPLETE && !allowed && decision == null) {
                throw new IllegalStateException(
                        "a complete explanation of a denied check needs its decision, DENIED or NOT_COVERED");
            }
            return new PermissionExplanation(this);
        }
    }
}
