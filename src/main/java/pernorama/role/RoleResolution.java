package pernorama.role;

import pernorama.permission.ContextPolicy;
import pernorama.permission.PermissionExplanation;
import pernorama.permission.PermissionResolver;

import java.util.ArrayList;
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
     * @param counted each assignment's decision, by index, if already
     *                known; {@code null} to ask each role as needed
     */
    private static PermissionResolver.Decision layered(List<RoleAssignment> assignments, String node, String context,
                                                       boolean denyOverrides, List<PermissionResolver.Decision> counted) {
        PermissionResolver.Decision decision = decideLayer(assignments, node, context, true, denyOverrides, counted);
        if (decision == PermissionResolver.Decision.NOT_COVERED) {
            decision = decideLayer(assignments, node, context, false, denyOverrides, counted);
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
            List<PermissionResolver.Decision> counted) {
        boolean permitted = false;
        boolean denied = false;
        for (int i = 0; i < assignments.size(); i++) {
            RoleAssignment assignment = assignments.get(i);
            if (!inLayer(assignment, context, scoped)) {
                continue;
            }
            PermissionResolver.Decision decision = counted == null ? assignment.role().decide(node) : counted.get(i);
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
     * assignments {@code contextPolicy} applies to {@code context}. Every
     * applicable role is explained; for a built-in policy the decision,
     * the deciding layer and the decisive roles come from {@link #layered}
     * itself. A custom policy is asked for its answer and reported with
     * the roles it was given, none of them marked decisive, since how it
     * combined them is not known.
     */
    static PermissionExplanation explain(List<RoleAssignment> applicable, String node, String context,
                                         PermissionResolutionPolicy policy, ContextPolicy contextPolicy) {
        List<PermissionExplanation> explained = new ArrayList<>(applicable.size());
        List<PermissionResolver.Decision> counted = new ArrayList<>(applicable.size());
        boolean allComplete = true;
        for (RoleAssignment assignment : applicable) {
            Role role = assignment.role();
            PermissionExplanation explanation = role.explain(node);
            explained.add(explanation);
            counted.add(role.decide(explanation));
            allComplete &= explanation.provenance() == PermissionExplanation.Provenance.COMPLETE;
        }

        boolean builtIn = policy == PermissionResolutionPolicy.ALLOW_OVERRIDES
                || policy == PermissionResolutionPolicy.DENY_OVERRIDES;
        if (!builtIn) {
            boolean allowed = policy.hasPermission(applicable, node, context);
            PermissionExplanation.Builder builder = PermissionExplanation.builder(node, context, allowed)
                    .contextPolicy(contextPolicy)
                    .provenance(applicable.isEmpty() ? PermissionExplanation.Provenance.UNAVAILABLE
                            : PermissionExplanation.Provenance.PARTIAL);
            for (int i = 0; i < applicable.size(); i++) {
                builder.contribution(new PermissionExplanation.Contribution(applicable.get(i), false, explained.get(i)));
            }
            return builder.build();
        }

        boolean denyOverrides = policy == PermissionResolutionPolicy.DENY_OVERRIDES;
        PermissionResolver.Decision decision = layered(applicable, node, context, denyOverrides, counted);
        PermissionExplanation.Layer layer = null;
        if (decideLayer(applicable, node, context, true, denyOverrides, counted)
                != PermissionResolver.Decision.NOT_COVERED) {
            layer = PermissionExplanation.Layer.EXACT_CONTEXT;
        } else if (decision != PermissionResolver.Decision.NOT_COVERED) {
            layer = PermissionExplanation.Layer.GLOBAL_FALLBACK;
        }

        PermissionExplanation.Builder builder =
                PermissionExplanation.builder(node, context, decision == PermissionResolver.Decision.PERMITTED)
                        .decision(decision)
                        .provenance(allComplete ? PermissionExplanation.Provenance.COMPLETE
                                : PermissionExplanation.Provenance.PARTIAL)
                        .contextPolicy(contextPolicy)
                        .resolutionPolicy(denyOverrides ? "DENY_OVERRIDES" : "ALLOW_OVERRIDES")
                        .decidingLayer(layer);
        for (int i = 0; i < applicable.size(); i++) {
            RoleAssignment assignment = applicable.get(i);
            boolean decisive = layer != null
                    && inLayer(assignment, context, layer == PermissionExplanation.Layer.EXACT_CONTEXT)
                    && counted.get(i) == decision;
            builder.contribution(new PermissionExplanation.Contribution(assignment, decisive, explained.get(i)));
        }
        return builder.build();
    }
}
