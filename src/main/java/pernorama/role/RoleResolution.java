package pernorama.role;

import pernorama.permission.ContextPolicy;
import pernorama.permission.PermissionExplanation;
import pernorama.permission.PermissionResolver;

import java.util.List;
import java.util.Objects;

/**
 * The context-first layering behind the built-in
 * {@link PermissionResolutionPolicy} constants, and the explanation of a
 * check through any policy. Both the check and its explanation go through
 * {@link #layered}, so the two cannot disagree on a built-in policy.
 */
final class RoleResolution {

    private RoleResolution() {
    }

    /** What the built-in policies return. */
    static boolean permits(List<RoleAssignment> assignments, String node, String context, boolean denyOverrides) {
        return layered(assignments, node, context, denyOverrides, null) == PermissionResolver.Decision.PERMITTED;
    }

    /**
     * Decides the layer of roles held in exactly {@code context} first, and
     * the rest — the roles held without a context that apply to it — only
     * if the first layer does not cover {@code node}.
     *
     * @param explained where to explain each role it consults, for an
     *                  explanation; {@code null} for the plain check
     */
    private static PermissionResolver.Decision layered(List<RoleAssignment> assignments, String node, String context,
                                                       boolean denyOverrides, Explained explained) {
        PermissionResolver.Decision decision = decideLayer(assignments, node, context, true, denyOverrides, explained);
        if (decision == PermissionResolver.Decision.NOT_COVERED) {
            decision = decideLayer(assignments, node, context, false, denyOverrides, explained);
        }
        return decision;
    }

    /**
     * The decision of one layer: the assignments held in {@code context}
     * if {@code scoped}, otherwise those held without a context. An
     * assignment held in some other context belongs to neither, even if
     * a caller passes one in. Under {@code denyOverrides}
     * any denial decides the layer; otherwise any permission does. A
     * layer in which no role covers the node is
     * {@link PermissionResolver.Decision#NOT_COVERED}.
     */
    private static PermissionResolver.Decision decideLayer(
            List<RoleAssignment> assignments, String node, String context, boolean scoped, boolean denyOverrides,
            Explained explained) {
        boolean permitted = false;
        boolean denied = false;
        for (int i = 0; i < assignments.size(); i++) {
            RoleAssignment assignment = assignments.get(i);
            if (!inLayer(assignment, context, scoped)) {
                continue;
            }
            PermissionResolver.Decision decision =
                    explained == null ? assignment.role().decide(node) : explained.decision(i);
            switch (decision) {
                case PERMITTED -> {
                    if (!denyOverrides) {
                        return PermissionResolver.Decision.PERMITTED;
                    }
                    permitted = true;
                }
                case DENIED -> {
                    if (denyOverrides) {
                        return PermissionResolver.Decision.DENIED;
                    }
                    denied = true;
                }
                case NOT_COVERED -> {
                }
            }
        }
        if (permitted) {
            return PermissionResolver.Decision.PERMITTED;
        }
        return denied ? PermissionResolver.Decision.DENIED : PermissionResolver.Decision.NOT_COVERED;
    }

    private static boolean inLayer(RoleAssignment assignment, String context, boolean scoped) {
        boolean inContext = Objects.equals(assignment.context(), context);
        return scoped ? inContext : !inContext && assignment.context() == null;
    }

    /**
     * Explains what {@code policy} answers for {@code applicable}, the
     * assignments {@code contextPolicy} applies to {@code context}.
     * <p>
     * The roles the check itself consults are consulted the same way and
     * in the same order — for a built-in policy through {@link #layered}
     * itself, which stops where the check stops — and an exception from
     * one of them propagates, as it would from the check. Every other
     * applicable role is then explained only to be reported: one that
     * throws is left out of the contributions and the provenance becomes
     * {@link PermissionExplanation.Provenance#PARTIAL}, since it could not
     * have changed the answer. A custom policy is asked for its answer
     * first; how it combined the roles is not known, so every role is
     * reported, none of them decisive.
     */
    static PermissionExplanation explain(List<RoleAssignment> applicable, String node, String context,
                                         PermissionResolutionPolicy policy, ContextPolicy contextPolicy) {
        Explained explained = new Explained(applicable, node);
        boolean builtIn = policy == PermissionResolutionPolicy.ALLOW_OVERRIDES
                || policy == PermissionResolutionPolicy.DENY_OVERRIDES;

        if (!builtIn) {
            boolean allowed = policy.hasPermission(applicable, node, context);
            explained.observeRest();
            PermissionExplanation.Builder builder = PermissionExplanation.builder(node, context, allowed)
                    .contextPolicy(contextPolicy)
                    .provenance(explained.anyReported() ? PermissionExplanation.Provenance.PARTIAL
                            : PermissionExplanation.Provenance.UNAVAILABLE);
            for (int i = 0; i < applicable.size(); i++) {
                if (explained.reported(i)) {
                    builder.contribution(new PermissionExplanation.Contribution(
                            applicable.get(i), false, explained.explanation(i)));
                }
            }
            return builder.build();
        }

        boolean denyOverrides = policy == PermissionResolutionPolicy.DENY_OVERRIDES;
        PermissionResolver.Decision decision = layered(applicable, node, context, denyOverrides, explained);
        // re-walks only roles layered already consulted, so nothing new is evaluated
        PermissionExplanation.Layer layer = null;
        if (decideLayer(applicable, node, context, true, denyOverrides, explained)
                != PermissionResolver.Decision.NOT_COVERED) {
            layer = PermissionExplanation.Layer.EXACT_CONTEXT;
        } else if (decision != PermissionResolver.Decision.NOT_COVERED) {
            layer = PermissionExplanation.Layer.GLOBAL_FALLBACK;
        }
        explained.observeRest();

        PermissionExplanation.Builder builder =
                PermissionExplanation.builder(node, context, decision == PermissionResolver.Decision.PERMITTED)
                        .decision(decision)
                        .provenance(explained.allComplete() ? PermissionExplanation.Provenance.COMPLETE
                                : PermissionExplanation.Provenance.PARTIAL)
                        .contextPolicy(contextPolicy)
                        .resolutionPolicy(denyOverrides ? "DENY_OVERRIDES" : "ALLOW_OVERRIDES")
                        .decidingLayer(layer);
        for (int i = 0; i < applicable.size(); i++) {
            if (!explained.reported(i)) {
                continue;
            }
            RoleAssignment assignment = applicable.get(i);
            boolean decisive = layer != null
                    && inLayer(assignment, context, layer == PermissionExplanation.Layer.EXACT_CONTEXT)
                    && explained.decision(i) == decision;
            builder.contribution(new PermissionExplanation.Contribution(assignment, decisive, explained.explanation(i)));
        }
        return builder.build();
    }

    /**
     * Each applicable role's explanation, made when first needed: by the
     * evaluation itself, through {@link #decision(int)}, or afterwards, by
     * {@link #observeRest()}. A role is asked at most once.
     */
    private static final class Explained {

        private final List<RoleAssignment> assignments;
        private final String node;
        private final PermissionExplanation[] explanations;
        private final boolean[] failed;

        Explained(List<RoleAssignment> assignments, String node) {
            this.assignments = assignments;
            this.node = node;
            this.explanations = new PermissionExplanation[assignments.size()];
            this.failed = new boolean[assignments.size()];
        }

        /** The decision of role {@code i}, explaining it now if needed; an exception propagates. */
        PermissionResolver.Decision decision(int i) {
            Role role = assignments.get(i).role();
            if (explanations[i] == null) {
                explanations[i] = role.explain(node);
            }
            return role.decide(explanations[i]);
        }

        /** Explains every role not consulted yet, leaving out any that throws. */
        void observeRest() {
            for (int i = 0; i < explanations.length; i++) {
                if (explanations[i] == null) {
                    try {
                        explanations[i] = assignments.get(i).role().explain(node);
                    } catch (RuntimeException e) {
                        failed[i] = true;
                    }
                }
            }
        }

        boolean reported(int i) {
            return explanations[i] != null;
        }

        PermissionExplanation explanation(int i) {
            return explanations[i];
        }

        boolean anyReported() {
            for (PermissionExplanation explanation : explanations) {
                if (explanation != null) {
                    return true;
                }
            }
            return false;
        }

        /** Whether every role was explained, each completely. */
        boolean allComplete() {
            for (int i = 0; i < explanations.length; i++) {
                if (failed[i] || explanations[i].provenance() != PermissionExplanation.Provenance.COMPLETE) {
                    return false;
                }
            }
            return true;
        }
    }
}
