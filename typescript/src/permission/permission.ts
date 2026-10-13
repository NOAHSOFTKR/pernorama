import { IllegalArgumentError, PermissionDeniedException } from '../error/errors.js';
import {
  checkSubject,
  explainSubject,
  isPermissionSubject,
  type PermissionSubject,
} from '../subject/permission-subject.js';
import type { PermissionExplanation } from './permission-explanation.js';
import { PermissionNode } from './permission-node.js';

/**
 * Entry point for checking a permission node against a
 * {@link PermissionSubject} from plain code, without a decorator.
 *
 * Two styles are supported: {@link Permission.check} returns a boolean for
 * an if/else style check, while {@link Permission.require} throws
 * {@link PermissionDeniedException} when the subject lacks the permission,
 * for a fail-fast guard-clause style.
 *
 * All three functions fail closed on a broken subject: an answer that is
 * not a boolean (a `Promise`, `undefined`) throws `IllegalStateError`
 * instead of being read as "allowed".
 */
export const Permission = {
  /**
   * Returns `true` if `subject` has `node` in `context`, or without a
   * context if it is `null` or omitted.
   *
   * @throws IllegalArgumentError if `subject` is not a subject, or the
   *         subject rejects `context` as empty
   * @throws InvalidPermissionException if the subject rejects `node` as
   *         not a valid node
   */
  check(subject: PermissionSubject, node: string | PermissionNode, context?: string | null): boolean {
    return checkSubject(requireSubject(subject), nameOf(node), context ?? null);
  },

  /**
   * Throws {@link PermissionDeniedException} if `subject` does not have
   * `node` in `context`; otherwise returns normally. The exception reports
   * the context as well as the node.
   *
   * @throws PermissionDeniedException if `subject` lacks `node` in `context`
   * @throws IllegalArgumentError if `subject` is not a subject, or the
   *         subject rejects `context` as empty
   * @throws InvalidPermissionException if the subject rejects `node` as
   *         not a valid node
   */
  require(subject: PermissionSubject, node: string | PermissionNode, context?: string | null): void {
    const name = nameOf(node);
    const requested = context ?? null;
    if (!checkSubject(requireSubject(subject), name, requested)) {
      throw new PermissionDeniedException(name, requested, subject);
    }
  },

  /**
   * Explains {@link Permission.check}: the subject's own `explain` if it
   * implements one, otherwise its answer with `UNAVAILABLE` provenance.
   * The counterpart of calling `subject.explain(node, context)` in Java,
   * where every subject has a default `explain`.
   *
   * @throws IllegalArgumentError if `subject` is not a subject, or the
   *         subject rejects `context` as empty
   * @throws InvalidPermissionException if the subject rejects `node` as
   *         not a valid node
   */
  explain(subject: PermissionSubject, node: string | PermissionNode, context?: string | null): PermissionExplanation {
    return explainSubject(requireSubject(subject), nameOf(node), context ?? null);
  },
} as const;

function requireSubject(subject: PermissionSubject): PermissionSubject {
  if (!isPermissionSubject(subject)) {
    throw new IllegalArgumentError('subject must be a PermissionSubject');
  }
  return subject;
}

function nameOf(node: string | PermissionNode): string {
  return node instanceof PermissionNode ? node.name : node;
}
