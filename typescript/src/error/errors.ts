import type { PermissionSubject } from '../subject/permission-subject.js';

/**
 * Base type for the errors Pernorama raises about permissions themselves:
 * an invalid permission string, a denied `require`, or — for decorated
 * methods — authorization that could not be evaluated at all.
 *
 * A plain permission check (`hasPermission`) on valid input never throws.
 */
export abstract class PernoramaException extends Error {
  protected constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

/**
 * Thrown when a value that is supposed to be a permission node or a
 * permission rule is syntactically invalid: blank, containing an empty
 * segment (`"users..create"`, `".users"`, `"users."`), or containing
 * characters outside the allowed segment charset.
 */
export class InvalidPermissionException extends PernoramaException {
  /** The offending value, exactly as it was passed in. */
  readonly value: unknown;

  constructor(value: unknown) {
    super(`Invalid permission: '${describe(value)}'`);
    this.value = value;
  }
}

/**
 * Thrown when a {@link PermissionSubject} attempts an action that requires
 * a permission node it does not have.
 */
export class PermissionDeniedException extends PernoramaException {
  /** The permission node that was required but missing. */
  readonly requiredPermission: string;
  /** The context the permission was required in, or `null` for none. */
  readonly context: string | null;
  /** The subject that lacked the required permission. Not enumerable, so it stays out of serialized errors. */
  declare readonly subject: PermissionSubject;

  constructor(requiredPermission: string, context: string | null | undefined, subject: PermissionSubject) {
    super(`Permission denied: ${requiredPermission}${context == null ? '' : ` in context ${context}`}`);
    this.requiredPermission = requiredPermission;
    this.context = context ?? null;
    Object.defineProperty(this, 'subject', { value: subject, enumerable: false, writable: false });
  }
}

/** Why a decorated method's authorization could not be evaluated. */
export type AuthorizationUnavailableReason =
  /** The subject resolver returned no subject, or something that is not one. */
  | 'SUBJECT_UNAVAILABLE'
  /** The subject resolver threw or rejected. */
  | 'SUBJECT_RESOLVER_FAILED'
  /** A context resolver was configured and returned `undefined` or an invalid context. */
  | 'CONTEXT_UNAVAILABLE'
  /** The context resolver threw or rejected. */
  | 'CONTEXT_RESOLVER_FAILED';

/**
 * Thrown by a method guarded with `@Perm` when the permission could not be
 * evaluated because the subject or the context it needs was not available.
 * The method body has not run. This is deliberately not a
 * {@link PermissionDeniedException}: nobody was denied, the question could
 * not be asked — typically "not authenticated" rather than "not allowed".
 *
 * Has no Java counterpart: Java's `PermissionInterceptor` is handed its
 * subject by the caller.
 */
export class AuthorizationUnavailableException extends PernoramaException {
  /** The permission node the method requires. */
  readonly requiredPermission: string;
  readonly reason: AuthorizationUnavailableReason;

  constructor(
    requiredPermission: string,
    reason: AuthorizationUnavailableReason,
    detail: string,
    options?: ErrorOptions,
  ) {
    super(`Cannot authorize ${requiredPermission}: ${detail}`, options);
    this.requiredPermission = requiredPermission;
    this.reason = reason;
  }
}

/**
 * An argument that is not a permission string was unacceptable: an empty
 * context, a blank role id, group limits that contradict each other.
 * Java's `IllegalArgumentException` (and, for a missing argument, its
 * `NullPointerException`).
 */
export class IllegalArgumentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IllegalArgumentError';
  }
}

/**
 * Something was asked of an object that its current state — or a policy's
 * answer — does not allow. Java's `IllegalStateException`.
 */
export class IllegalStateError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'IllegalStateError';
  }
}

/**
 * `grant` or `revoke` was called on a read-only subject. Java's
 * `UnsupportedOperationException`.
 */
export class UnsupportedOperationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsupportedOperationError';
  }
}

function describe(value: unknown): string {
  if (typeof value === 'string') {
    return value;
  }
  if (value === null || value === undefined || typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return typeof value;
}
