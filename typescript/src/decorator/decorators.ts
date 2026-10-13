import {
  AuthorizationUnavailableException,
  type AuthorizationUnavailableReason,
  IllegalArgumentError,
  IllegalStateError,
  PermissionDeniedException,
} from '../error/errors.js';
import { isBlank } from '../internal/java-strings.js';
import { PermissionGrant } from '../permission/permission-grant.js';
import { validateNode } from '../permission/syntax.js';
import { checkSubject, isPermissionSubject, type PermissionSubject } from '../subject/permission-subject.js';
import {
  classRecordOf,
  ensureMetadataSymbol,
  guardedRecordOf,
  type MethodRecord,
  nodeOf,
  recordGuarded,
} from './metadata.js';

/** One call of a method guarded with `@Perm`, as handed to the resolvers. */
export interface PermInvocation {
  /** The permission node the method requires, with its class's `@PermGroup` applied. */
  readonly permission: string;
  /**
   * `this` of the call: the instance for an instance method, the class for
   * a static one — or whatever the caller bound, including `undefined` for
   * a method that was detached from its object.
   */
  readonly target: unknown;
  /** The arguments of the call. */
  readonly args: readonly unknown[];
  /** The name of the guarded method. */
  readonly methodName: string | symbol;
  /** Whether the guarded method is static. */
  readonly isStatic: boolean;
}

/**
 * Finds the subject a guarded call is made on behalf of — from the
 * arguments, from the instance, from a request-scoped object the
 * application passes along. Return `null` or `undefined` when there is
 * none; the call then fails with {@link AuthorizationUnavailableException}.
 */
export type SubjectResolver = (invocation: PermInvocation) => PermissionSubject | null | undefined;

/**
 * Finds the context a guarded call is checked in. Return a non-empty
 * string to check in that context, or `null` to check without one —
 * explicitly. Returning `undefined` means the context could not be
 * determined, and the call fails with
 * {@link AuthorizationUnavailableException} rather than falling back to a
 * check without a context, which could permit what the context denies.
 */
export type ContextResolver = (invocation: PermInvocation) => string | null | undefined;

/** A {@link SubjectResolver} that may answer asynchronously. */
export type AsyncSubjectResolver = (
  invocation: PermInvocation,
) => PermissionSubject | null | undefined | PromiseLike<PermissionSubject | null | undefined>;

/** A {@link ContextResolver} that may answer asynchronously. */
export type AsyncContextResolver = (
  invocation: PermInvocation,
) => string | null | undefined | PromiseLike<string | null | undefined>;

/** How the decorators made by {@link createPermissionDecorators} resolve what they check. */
export interface PermissionDecoratorOptions {
  /** Finds the subject of a guarded call. Required: there is no default and no global. */
  readonly subject: SubjectResolver;
  /**
   * Finds the context of a guarded call. Without one, guarded methods are
   * checked without a context, as Java's `PermissionInterceptor` does.
   */
  readonly context?: ContextResolver;
}

/** {@link PermissionDecoratorOptions} whose resolvers may answer asynchronously. */
export interface AsyncPermissionDecoratorOptions {
  readonly subject: AsyncSubjectResolver;
  readonly context?: AsyncContextResolver;
}

/** Per-method overrides of the resolvers the decorators were created with. */
export interface PermOptions {
  /** Finds the subject for this method instead of the default resolver. */
  readonly subject?: SubjectResolver;
  /**
   * Finds the context for this method instead of the default resolver;
   * `null` checks this method without a context even if a default
   * resolver is configured.
   */
  readonly context?: ContextResolver | null;
}

/** {@link PermOptions} whose resolvers may answer asynchronously. */
export interface AsyncPermOptions {
  readonly subject?: AsyncSubjectResolver;
  readonly context?: AsyncContextResolver | null;
}

type Method<This, Args extends unknown[], Return> = (this: This, ...args: Args) => Return;
type Class = abstract new (...args: never[]) => unknown;

/**
 * What `@Perm(...)` evaluates to: a decorator for a method, which it
 * guards, or for a class, on which it only declares a node for
 * `PermissionRegistry`.
 *
 * @typeParam R what a guarded method has to return: anything for
 *            synchronous decorators, a promise for asynchronous ones
 */
export interface PermDecorator<R = unknown> {
  <This, Args extends unknown[], Return extends R>(
    method: Method<This, Args, Return>,
    context: ClassMethodDecoratorContext<This, Method<This, Args, Return>>,
  ): Method<This, Args, Return>;
  <T extends Class>(type: T, context: ClassDecoratorContext<T>): void;
}

/** What `@PermGroup(...)` evaluates to: a class decorator. */
export type PermGroupDecorator = <T extends Class>(type: T, context: ClassDecoratorContext<T>) => void;

/** The decorators made by {@link createPermissionDecorators}. */
export interface PermissionDecorators {
  /**
   * On a method: requires the permission node `value` — relative to the
   * declaring class's `@PermGroup`, if it has one — before the method
   * body runs. On a class: declares a node for `PermissionRegistry`, and
   * guards nothing.
   *
   * @throws InvalidPermissionException when the class is defined, if
   *         `value` is not a valid permission node
   */
  Perm(value: string, options?: PermOptions): PermDecorator;
  /**
   * Groups the `@Perm` methods declared in the decorated class under a
   * common node prefix: `@PermGroup('users')` and `@Perm('create')` yield
   * `"users.create"`.
   */
  PermGroup(value: string): PermGroupDecorator;
}

/** The decorators made by {@link createAsyncPermissionDecorators}. */
export interface AsyncPermissionDecorators {
  /**
   * As {@link PermissionDecorators.Perm}, for methods that return a
   * promise: the resolvers may be asynchronous, and every failure is a
   * rejection.
   */
  Perm(value: string, options?: AsyncPermOptions): PermDecorator<PromiseLike<unknown>>;
  /** As {@link PermissionDecorators.PermGroup}. */
  PermGroup(value: string): PermGroupDecorator;
}

/**
 * Creates `@Perm` and `@PermGroup` standard (TC39) decorators that resolve
 * the subject — and optionally the context — of each guarded call with the
 * given strategy:
 *
 * ```ts
 * // auth.ts
 * export const { Perm, PermGroup } = createPermissionDecorators({
 *   subject: ({ args }) => (args[0] as Actor).permissions,
 * });
 *
 * // user-service.ts
 * @PermGroup('users')
 * class UserService {
 *   @Perm('create')
 *   create(actor: Actor, name: string) { ... } // requires users.create
 * }
 * ```
 *
 * There is no global `@Perm` and no implicit "current user": decorators
 * only exist bound to an explicit strategy, and an application that has
 * two kinds of callers creates two sets.
 *
 * ## What a guarded call does
 * 1. resolves the subject, then the context — in that order;
 * 2. checks the permission with `subject.hasPermission(node, context)`;
 * 3. only then runs the method body, with the same `this` and arguments.
 *
 * It fails closed: if the subject or context cannot be resolved the call
 * throws {@link AuthorizationUnavailableException}, if the permission is
 * missing it throws {@link PermissionDeniedException}, and an error thrown
 * by `hasPermission` propagates. In every one of those cases the method
 * body does not run.
 *
 * These resolvers are synchronous, so a guarded method keeps its own
 * return type and timing; a resolver that returns a promise is rejected as
 * "no subject". A denial is thrown synchronously, except from a native
 * `async` method, where it is a rejection of the promise the method
 * returns. Use {@link createAsyncPermissionDecorators} when resolving has
 * to wait for something.
 */
export function createPermissionDecorators(options: PermissionDecoratorOptions): PermissionDecorators {
  return create(options, false) as PermissionDecorators;
}

/**
 * {@link createPermissionDecorators} for resolvers that may be
 * asynchronous — a subject loaded from a database, say:
 *
 * ```ts
 * export const { Perm, PermGroup } = createAsyncPermissionDecorators({
 *   subject: async ({ args }) => loadSubject((args[0] as Request).userId),
 *   context: ({ args }) => `academy:${(args[0] as Request).academyId}`,
 * });
 * ```
 *
 * A method guarded this way always returns a promise, and every failure —
 * resolution, denial, an error from `hasPermission` — is a rejection of
 * it. Its type only accepts methods that already return a promise, so the
 * guard never changes what a caller sees.
 */
export function createAsyncPermissionDecorators(options: AsyncPermissionDecoratorOptions): AsyncPermissionDecorators {
  return create(options, true) as AsyncPermissionDecorators;
}

function create(defaults: AsyncPermissionDecoratorOptions, asynchronous: boolean): unknown {
  if (typeof defaults !== 'object' || defaults === null || typeof defaults.subject !== 'function') {
    throw new IllegalArgumentError('a subject resolver is required: { subject: (invocation) => ... }');
  }
  if (defaults.context !== undefined && typeof defaults.context !== 'function') {
    throw new IllegalArgumentError('context must be a function');
  }
  ensureMetadataSymbol();

  function Perm(value: string, options: AsyncPermOptions = {}) {
    validateNode(value);
    if (typeof options !== 'object' || options === null) {
      throw new IllegalArgumentError('@Perm options must be an object');
    }
    if (options.subject !== undefined && typeof options.subject !== 'function') {
      throw new IllegalArgumentError('@Perm subject must be a function');
    }
    if (options.context !== undefined && options.context !== null && typeof options.context !== 'function') {
      throw new IllegalArgumentError('@Perm context must be a function or null');
    }
    const resolvers: Resolvers = {
      subject: options.subject ?? defaults.subject,
      context: options.context === undefined ? (defaults.context ?? null) : options.context,
    };

    return function decorate(target: unknown, rawContext: unknown): unknown {
      const context = contextOf(rawContext, '@Perm');
      const kind = context.kind;
      if (kind === 'class') {
        if (options.subject !== undefined || options.context !== undefined) {
          throw new IllegalArgumentError('@Perm on a class only declares a node; it takes no resolvers');
        }
        const record = classRecordOf(context.metadata, '@Perm');
        if (record.typePermission !== null) {
          throw new IllegalStateError(`${describeClass(context)} already declares @Perm('${record.typePermission}')`);
        }
        record.typePermission = value;
        return undefined;
      }
      if (kind !== 'method' || typeof target !== 'function') {
        throw new IllegalArgumentError(
          `@Perm guards methods and declares nodes on classes; it cannot decorate a ${kind}`,
        );
      }
      if (guardedRecordOf(target) !== null) {
        // Java's @Perm is not repeatable either: one method, one node
        throw new IllegalStateError(
          `${String(context.name)} already has @Perm; a method requires one permission node. ` +
            'Check further permissions in the method body with Permission.require',
        );
      }

      const owner = classRecordOf(context.metadata, '@Perm');
      const record: MethodRecord = Object.freeze({
        value,
        name: context.name ?? '',
        isStatic: context.static === true,
        isPrivate: context.private === true,
        owner,
      });
      owner.methods.push(record);

      const guarded = guard(target as AnyFunction, record, resolvers, asynchronous);
      recordGuarded(guarded, record);
      return guarded;
    };
  }

  function PermGroup(value: string) {
    if (typeof value !== 'string') {
      throw new IllegalArgumentError('@PermGroup takes a string');
    }
    if (!isBlank(value)) {
      validateNode(value);
    }
    return function decorate(_type: unknown, rawContext: unknown): void {
      const context = contextOf(rawContext, '@PermGroup');
      const kind = context.kind;
      if (kind !== 'class') {
        throw new IllegalArgumentError(`@PermGroup decorates a class; it cannot decorate a ${kind}`);
      }
      const record = classRecordOf(context.metadata, '@PermGroup');
      if (record.grouped) {
        throw new IllegalStateError(`${describeClass(context)} already has @PermGroup`);
      }
      record.grouped = true;
      record.group = value;
    };
  }

  return Object.freeze({ Perm, PermGroup });
}

type AnyFunction = (this: unknown, ...args: unknown[]) => unknown;

interface Resolvers {
  readonly subject: AsyncSubjectResolver;
  readonly context: AsyncContextResolver | null;
}

interface DecoratorContext {
  readonly kind: string;
  readonly name: string | symbol | undefined;
  readonly static?: boolean;
  readonly private?: boolean;
  readonly metadata?: unknown;
}

function contextOf(context: unknown, decorator: string): DecoratorContext {
  if (typeof context !== 'object' || context === null || typeof (context as DecoratorContext).kind !== 'string') {
    // experimentalDecorators passes (target, propertyKey, descriptor) instead of a context object
    throw new IllegalStateError(
      `${decorator} is a standard (TC39) decorator and was called as a legacy one. ` +
        'Remove "experimentalDecorators" from the TypeScript configuration.',
    );
  }
  return context as DecoratorContext;
}

function describeClass(context: DecoratorContext): string {
  return typeof context.name === 'string' && context.name.length > 0 ? `class ${context.name}` : 'the class';
}

/** The function that replaces a `@Perm` method: authorize, then run the original. */
function guard(original: AnyFunction, record: MethodRecord, resolvers: Resolvers, asynchronous: boolean): AnyFunction {
  const rejects = asynchronous || Object.prototype.toString.call(original) === '[object AsyncFunction]';

  const guarded = function (this: unknown, ...args: unknown[]): unknown {
    if (asynchronous) {
      return authorizeAsync(this, args, record, resolvers).then(() => Reflect.apply(original, this, args));
    }
    try {
      authorize(this, args, record, resolvers);
    } catch (error) {
      if (rejects) {
        return Promise.reject(error);
      }
      throw error;
    }
    return Reflect.apply(original, this, args);
  };

  Object.defineProperty(guarded, 'name', { value: original.name, configurable: true });
  Object.defineProperty(guarded, 'length', { value: original.length, configurable: true });
  return guarded;
}

function invocationOf(target: unknown, args: unknown[], record: MethodRecord): PermInvocation {
  return Object.freeze({
    permission: nodeOf(record),
    target,
    args: Object.freeze([...args]),
    methodName: record.name,
    isStatic: record.isStatic,
  });
}

function authorize(target: unknown, args: unknown[], record: MethodRecord, resolvers: Resolvers): void {
  const invocation = invocationOf(target, args, record);
  const subject = attempt(invocation, 'SUBJECT_RESOLVER_FAILED', () => resolvers.subject(invocation));
  const context =
    resolvers.context === null
      ? null
      : attempt(invocation, 'CONTEXT_RESOLVER_FAILED', () => resolvers.context!(invocation));
  decide(invocation, subject, context, resolvers.context !== null);
}

async function authorizeAsync(
  target: unknown,
  args: unknown[],
  record: MethodRecord,
  resolvers: Resolvers,
): Promise<void> {
  const invocation = invocationOf(target, args, record);
  let subject: unknown;
  try {
    subject = await resolvers.subject(invocation);
  } catch (cause) {
    throw resolverFailed(invocation, 'SUBJECT_RESOLVER_FAILED', cause);
  }
  let context: unknown = null;
  if (resolvers.context !== null) {
    try {
      context = await resolvers.context(invocation);
    } catch (cause) {
      throw resolverFailed(invocation, 'CONTEXT_RESOLVER_FAILED', cause);
    }
  }
  decide(invocation, subject, context, resolvers.context !== null);
}

function attempt(invocation: PermInvocation, reason: AuthorizationUnavailableReason, resolve: () => unknown): unknown {
  try {
    return resolve();
  } catch (cause) {
    throw resolverFailed(invocation, reason, cause);
  }
}

function resolverFailed(
  invocation: PermInvocation,
  reason: AuthorizationUnavailableReason,
  cause: unknown,
): AuthorizationUnavailableException {
  const what = reason === 'SUBJECT_RESOLVER_FAILED' ? 'subject' : 'context';
  return new AuthorizationUnavailableException(invocation.permission, reason, `the ${what} resolver failed`, {
    cause,
  });
}

/** The check itself, once the resolvers have answered. Returns only if the call is permitted. */
function decide(invocation: PermInvocation, subject: unknown, context: unknown, contextResolved: boolean): void {
  const node = invocation.permission;
  if (!isPermissionSubject(subject)) {
    const got =
      subject === null || subject === undefined
        ? 'no subject'
        : isThenable(subject)
          ? 'a Promise; use createAsyncPermissionDecorators for an asynchronous resolver'
          : 'something that is not a PermissionSubject';
    throw new AuthorizationUnavailableException(node, 'SUBJECT_UNAVAILABLE', `the subject resolver returned ${got}`);
  }
  let requested: string | null = null;
  if (contextResolved) {
    if (context === undefined) {
      throw new AuthorizationUnavailableException(
        node,
        'CONTEXT_UNAVAILABLE',
        'the context resolver returned undefined; return null to check without a context',
      );
    }
    if (!PermissionGrant.isValidContext(context)) {
      const got = isThenable(context)
        ? 'a Promise; use createAsyncPermissionDecorators for an asynchronous resolver'
        : 'an invalid context';
      throw new AuthorizationUnavailableException(
        node,
        'CONTEXT_UNAVAILABLE',
        `the context resolver returned ${got}; a context is a non-empty string, or null for none`,
      );
    }
    requested = context;
  }
  if (!checkSubject(subject, node, requested)) {
    throw new PermissionDeniedException(node, requested, subject);
  }
}

function isThenable(value: unknown): boolean {
  return (
    (typeof value === 'object' || typeof value === 'function') &&
    value !== null &&
    typeof (value as { then?: unknown }).then === 'function'
  );
}
