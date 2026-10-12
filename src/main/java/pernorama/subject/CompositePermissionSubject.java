package pernorama.subject;

import pernorama.exception.InvalidPermissionException;
import pernorama.permission.PermissionExplanation;
import pernorama.permission.PermissionGrant;
import pernorama.permission.PermissionNode;
import pernorama.permission.PermissionResolver;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * A read-only {@link PermissionSubject} that answers from several other
 * subjects at once — the usual "a user holds roles, and each role
 * carries permissions" shape:
 *
 * <pre>{@code
 * PermissionSubject admins = new MemoryPermissionSubject(List.of("users.*"));
 * PermissionSubject own = new MemoryPermissionSubject(List.of("profile.edit"));
 *
 * PermissionSubject user = new CompositePermissionSubject(own, admins);
 * user.hasPermission("users.create"); // true, from the admins role
 * user.hasPermission("profile.edit"); // true, from the user's own grants
 * }</pre>
 *
 * <h2>How the answer is combined</h2>
 * {@link #hasPermission(String, String)} is {@code true} if <b>any</b>
 * source says {@code true} for the same node in the same context. Each
 * source evaluates its own rules on its own, including any deny rules it
 * holds, so <b>a deny rule only limits the
 * source that holds it</b>: if one role denies {@code users.delete} but
 * another source grants it, the answer is {@code true}. Put a permission
 * in fewer sources rather than expecting a deny in one source to
 * override another. A composite with no sources permits nothing.
 * <p>
 * The composite passes the context through unchanged and does not
 * interpret it: each source applies its own
 * {@link pernorama.permission.ContextPolicy}, so build every source from
 * the same {@link pernorama.Pernorama} instance.
 *
 * <h2>Read-only</h2>
 * {@link #grant(String, String)} and {@link #revoke(String, String)} throw
 * {@link UnsupportedOperationException}: a composite has no storage of
 * its own, and silently picking one of the sources to write to would
 * make "granted to the role" and "granted to the user" indistinguishable
 * at the call site. Modify the source you actually mean instead.
 *
 * <h2>Thread safety</h2>
 * The composite itself is immutable: the source list is copied when it
 * is constructed and never changes. Whether concurrent use is safe
 * therefore depends entirely on the sources it was given; see
 * {@link MemoryPermissionSubject} for one that is safe.
 */
public final class CompositePermissionSubject implements PermissionSubject {

    private final List<PermissionSubject> sources;

    /** Creates a composite over the given subjects, consulted in order. */
    public CompositePermissionSubject(PermissionSubject... sources) {
        this(Arrays.asList(Objects.requireNonNull(sources, "sources")));
    }

    /** Creates a composite over the given subjects, consulted in iteration order. */
    public CompositePermissionSubject(Collection<? extends PermissionSubject> sources) {
        Objects.requireNonNull(sources, "sources");
        List<PermissionSubject> copy = new ArrayList<>(sources.size());
        for (PermissionSubject source : sources) {
            copy.add(Objects.requireNonNull(source, "source"));
        }
        this.sources = List.copyOf(copy);
    }

    /**
     * Returns {@code true} if any source has {@code node} in
     * {@code context}. Sources are consulted in order and the first
     * {@code true} wins, so a source that would have thrown is not
     * necessarily reached.
     *
     * @throws InvalidPermissionException if {@code node} is not a
     *         syntactically valid permission node
     * @throws IllegalArgumentException if {@code context} is empty
     */
    @Override
    public boolean hasPermission(String node, String context) {
        if (!PermissionNode.isValid(node)) {
            throw new InvalidPermissionException(node);
        }
        PermissionGrant.requireValidContext(context);
        for (PermissionSubject source : sources) {
            if (source.hasPermission(node, context)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Explains {@link #hasPermission(String, String)} with one
     * {@linkplain PermissionExplanation#contributions() contribution} per
     * source, in order, each carrying the source's own explanation, and
     * {@linkplain PermissionExplanation#resolutionPolicy() resolution policy}
     * {@code "ANY_SOURCE"}. Unlike {@code hasPermission}, every source is
     * asked, so a source that would throw always does.
     * <p>
     * If the composite permits the node, the sources that permit it are
     * {@linkplain PermissionExplanation.Contribution#decisive() decisive}.
     * Otherwise the decision is {@link PermissionResolver.Decision#DENIED}
     * if some source explicitly denies the node — those sources being
     * decisive — {@link PermissionResolver.Decision#NOT_COVERED} if every
     * source reports that nothing covers it, and unknown if neither can be
     * told. The provenance is {@link PermissionExplanation.Provenance#COMPLETE}
     * only if the decision is known and every source's explanation is
     * complete.
     *
     * @throws InvalidPermissionException if {@code node} is not a
     *         syntactically valid permission node
     * @throws IllegalArgumentException if {@code context} is empty
     */
    @Override
    public PermissionExplanation explain(String node, String context) {
        if (!PermissionNode.isValid(node)) {
            throw new InvalidPermissionException(node);
        }
        PermissionGrant.requireValidContext(context);

        List<PermissionExplanation> explained = new ArrayList<>(sources.size());
        boolean allowed = false;
        boolean anyDenied = false;
        boolean allNotCovered = true;
        boolean allComplete = true;
        boolean anyInformative = false;
        for (PermissionSubject source : sources) {
            PermissionExplanation explanation = source.explain(node, context);
            explained.add(explanation);
            PermissionResolver.Decision decision = explanation.decision().orElse(null);
            allowed |= explanation.allowed();
            anyDenied |= decision == PermissionResolver.Decision.DENIED;
            allNotCovered &= decision == PermissionResolver.Decision.NOT_COVERED;
            allComplete &= explanation.provenance() == PermissionExplanation.Provenance.COMPLETE;
            anyInformative |= explanation.provenance() != PermissionExplanation.Provenance.UNAVAILABLE;
        }

        PermissionResolver.Decision decision;
        if (allowed) {
            decision = PermissionResolver.Decision.PERMITTED;
        } else if (anyDenied) {
            decision = PermissionResolver.Decision.DENIED;
        } else if (allNotCovered) {
            decision = PermissionResolver.Decision.NOT_COVERED;
        } else {
            decision = null;
        }

        PermissionExplanation.Builder builder = PermissionExplanation.builder(node, context, allowed)
                .resolutionPolicy("ANY_SOURCE");
        if (decision != null) {
            builder.decision(decision)
                    .provenance(allComplete ? PermissionExplanation.Provenance.COMPLETE
                            : PermissionExplanation.Provenance.PARTIAL);
        } else if (anyInformative) {
            builder.provenance(PermissionExplanation.Provenance.PARTIAL);
        }
        for (int i = 0; i < sources.size(); i++) {
            PermissionExplanation explanation = explained.get(i);
            // nothing decides a node no source covers
            boolean decisive = decision != null && decision != PermissionResolver.Decision.NOT_COVERED
                    && explanation.decision().orElse(null) == decision;
            builder.contribution(new PermissionExplanation.Contribution(sources.get(i), decisive, explanation));
        }
        return builder.build();
    }

    /**
     * Always throws: a composite is read-only.
     *
     * @throws UnsupportedOperationException always
     */
    @Override
    public void grant(String node, String context) {
        throw new UnsupportedOperationException(
                "CompositePermissionSubject is read-only; grant on the source subject instead");
    }

    /**
     * Always throws: a composite is read-only.
     *
     * @throws UnsupportedOperationException always
     */
    @Override
    public void revoke(String node, String context) {
        throw new UnsupportedOperationException(
                "CompositePermissionSubject is read-only; revoke on the source subject instead");
    }

    /** The subjects this composite consults, in the order it consults them. */
    public List<PermissionSubject> sources() {
        return sources;
    }
}
