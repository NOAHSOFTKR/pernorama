import { IllegalArgumentError, UnsupportedOperationError } from '../error/errors.js';
import { Decision } from '../permission/decision.js';
import { Contribution, PermissionExplanation, Provenance } from '../permission/permission-explanation.js';
import { PermissionGrant } from '../permission/permission-grant.js';
import { validateNode } from '../permission/syntax.js';
import { checkSubject, explainSubject, isPermissionSubject, type PermissionSubject } from './permission-subject.js';

/**
 * A read-only {@link PermissionSubject} that answers from several other
 * subjects at once — the usual "a user holds roles, and each role carries
 * permissions" shape:
 *
 * ```ts
 * const admins = new MemoryPermissionSubject(['users.*']);
 * const own = new MemoryPermissionSubject(['profile.edit']);
 *
 * const user = new CompositePermissionSubject(own, admins);
 * user.hasPermission('users.create'); // true, from the admins role
 * user.hasPermission('profile.edit'); // true, from the user's own grants
 * ```
 *
 * ## How the answer is combined
 * `hasPermission` is `true` if **any** source says `true` for the same
 * node in the same context. Each source evaluates its own rules on its
 * own, including any deny rules it holds, so **a deny rule only limits the
 * source that holds it**: if one role denies `users.delete` but another
 * source grants it, the answer is `true`. Put a permission in fewer
 * sources rather than expecting a deny in one source to override another.
 * A composite with no sources permits nothing.
 *
 * The composite passes the context through unchanged and does not
 * interpret it: each source applies its own `ContextPolicy`, so build
 * every source from the same `Pernorama` instance.
 *
 * ## Read-only
 * `grant` and `revoke` throw `UnsupportedOperationError`: a composite has
 * no storage of its own, and silently picking one of the sources to write
 * to would make "granted to the role" and "granted to the user"
 * indistinguishable at the call site. Modify the source you actually mean.
 *
 * The composite itself is immutable: the source list is copied when it is
 * constructed and never changes.
 */
export class CompositePermissionSubject implements PermissionSubject {
  readonly #sources: readonly PermissionSubject[];

  /** Creates a composite over the given subjects, consulted in order. */
  constructor(...sources: PermissionSubject[]);
  /** Creates a composite over the given subjects, consulted in iteration order. */
  constructor(sources: Iterable<PermissionSubject>);
  constructor(...args: PermissionSubject[] | [Iterable<PermissionSubject>]) {
    const first: unknown = args[0];
    const given: Iterable<unknown> =
      args.length === 1 && !isPermissionSubject(first) && isIterable(first) ? first : args;
    const copy: PermissionSubject[] = [];
    for (const source of given) {
      if (!isPermissionSubject(source)) {
        throw new IllegalArgumentError('every source must be a PermissionSubject');
      }
      copy.push(source);
    }
    this.#sources = Object.freeze(copy);
  }

  /**
   * Returns `true` if any source has `node` in `context`. Sources are
   * consulted in order and the first `true` wins, so a source that would
   * have thrown is not necessarily reached.
   *
   * @throws InvalidPermissionException if `node` is not a valid node
   * @throws IllegalArgumentError if `context` is empty
   */
  hasPermission(node: string, context?: string | null): boolean {
    validateNode(node);
    const requested = PermissionGrant.requireValidContext(context);
    for (const source of this.#sources) {
      if (checkSubject(source, node, requested)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Explains {@link hasPermission} with one contribution per source, in
   * order, each carrying the source's own explanation, and resolution
   * policy `"ANY_SOURCE"`. Each source is asked once, through its own
   * `explain` if it has one.
   *
   * The sources `hasPermission` would consult — every one up to the first
   * that permits — are consulted in the same order, and an error from one
   * of them propagates, as it would from the check. The sources after the
   * first that permits cannot change the answer and are explained only to
   * be reported: one that throws is left out of the contributions, and the
   * provenance is then at most `PARTIAL`.
   *
   * If the composite permits the node, the sources that permit it are
   * decisive. Otherwise the decision is `DENIED` if some source explicitly
   * denies the node — those sources being decisive — `NOT_COVERED` if
   * every source reports that nothing covers it, and unknown (`null`) if
   * neither can be told. The provenance is `COMPLETE` only if the decision
   * is known and every source's explanation is complete.
   *
   * @throws InvalidPermissionException if `node` is not a valid node
   * @throws IllegalArgumentError if `context` is empty
   */
  explain(node: string, context?: string | null): PermissionExplanation {
    validateNode(node);
    const requested = PermissionGrant.requireValidContext(context);

    // Ask the sources hasPermission would ask, in its order, letting an
    // error propagate as it would there; once one permits, the rest are
    // only observed, and one that throws is left out.
    const explained: (PermissionExplanation | null)[] = [];
    let allowed = false;
    let anyFailed = false;
    for (const source of this.#sources) {
      if (!allowed) {
        const explanation = explainSubject(source, node, requested);
        explained.push(explanation);
        allowed = explanation.allowed;
      } else {
        try {
          explained.push(explainSubject(source, node, requested));
        } catch {
          explained.push(null);
          anyFailed = true;
        }
      }
    }

    let anyDenied = false;
    let allNotCovered = true;
    let allComplete = !anyFailed;
    let anyInformative = false;
    for (const explanation of explained) {
      if (explanation === null) {
        continue;
      }
      anyDenied ||= explanation.decision === Decision.DENIED;
      allNotCovered &&= explanation.decision === Decision.NOT_COVERED;
      allComplete &&= explanation.provenance === Provenance.COMPLETE;
      anyInformative ||= explanation.provenance !== Provenance.UNAVAILABLE;
    }

    let decision: Decision | null;
    if (allowed) {
      decision = Decision.PERMITTED;
    } else if (anyDenied) {
      decision = Decision.DENIED;
    } else if (allNotCovered) {
      decision = Decision.NOT_COVERED;
    } else {
      decision = null;
    }

    const builder = PermissionExplanation.builder(node, requested, allowed).resolutionPolicy('ANY_SOURCE');
    if (decision !== null) {
      builder.decision(decision).provenance(allComplete ? Provenance.COMPLETE : Provenance.PARTIAL);
    } else if (anyInformative) {
      builder.provenance(Provenance.PARTIAL);
    }
    explained.forEach((explanation, i) => {
      if (explanation === null) {
        return;
      }
      // nothing decides a node no source covers
      const decisive =
        decision !== null && decision !== Decision.NOT_COVERED && explanation.decision === decision;
      builder.contribution(new Contribution(this.#sources[i]!, decisive, explanation));
    });
    return builder.build();
  }

  /**
   * Always throws: a composite is read-only.
   *
   * @throws UnsupportedOperationError always
   */
  grant(_rule: string, _context?: string | null): never {
    throw new UnsupportedOperationError(
      'CompositePermissionSubject is read-only; grant on the source subject instead',
    );
  }

  /**
   * Always throws: a composite is read-only.
   *
   * @throws UnsupportedOperationError always
   */
  revoke(_rule: string, _context?: string | null): never {
    throw new UnsupportedOperationError(
      'CompositePermissionSubject is read-only; revoke on the source subject instead',
    );
  }

  /** The subjects this composite consults, in the order it consults them. */
  get sources(): readonly PermissionSubject[] {
    return this.#sources;
  }
}

function isIterable(value: unknown): value is Iterable<unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { [Symbol.iterator]?: unknown })[Symbol.iterator] === 'function'
  );
}
