import { IllegalArgumentError, IllegalStateError } from '../error/errors.js';
import { isBlank } from '../internal/java-strings.js';
import { validateNode } from '../permission/syntax.js';

/**
 * What `@PermGroup` and `@Perm` recorded on one class. Kept in the class's
 * own decorator metadata object, which is the one thing a class's method
 * decorators and its class decorators share.
 */
export interface ClassRecord {
  /** The `@PermGroup` value, or `null` if the class has none. */
  group: string | null;
  /** Whether `@PermGroup` was applied, so that a second one is an error. */
  grouped: boolean;
  /** The class-level `@Perm` value, or `null`. */
  typePermission: string | null;
  /** The `@Perm` methods declared on the class, in decoration order. */
  readonly methods: MethodRecord[];
}

/** One `@Perm` method. */
export interface MethodRecord {
  /** The value given to `@Perm`, relative to the class's group if it has one. */
  readonly value: string;
  readonly name: string | symbol;
  readonly isStatic: boolean;
  readonly isPrivate: boolean;
  readonly owner: ClassRecord;
}

const RECORD = Symbol.for('@noahsoft/pernorama/decorator-metadata/v1');

/** The guarded function installed by `@Perm` -> what it was declared with. */
const GUARDED = new WeakMap<object, MethodRecord>();

/**
 * Makes sure `Symbol.metadata` exists, so that a compiler's decorator
 * helpers create the metadata object the decorators record into. Runtimes
 * do not define it yet; TypeScript's and esbuild's emit both look it up
 * when a decorated class is defined. `Symbol.for('Symbol.metadata')` is
 * the value esbuild falls back to, so the two agree.
 *
 * Called when decorators are created — before any class using them is
 * defined — rather than when this module is imported, which keeps
 * importing the package free of side effects.
 */
export function ensureMetadataSymbol(): symbol {
  const symbols = Symbol as unknown as { metadata?: symbol };
  if (typeof symbols.metadata !== 'symbol') {
    Object.defineProperty(Symbol, 'metadata', {
      value: Symbol.for('Symbol.metadata'),
      writable: false,
      enumerable: false,
      configurable: false,
    });
  }
  return symbols.metadata!;
}

/** The record of the class being decorated, created on first use. */
export function classRecordOf(metadata: unknown, decorator: string): ClassRecord {
  if (typeof metadata !== 'object' || metadata === null) {
    throw new IllegalStateError(
      `${decorator} needs standard decorator metadata (context.metadata), which this build did not provide. ` +
        'Compile with TypeScript 5.2 or later without "experimentalDecorators", and create the decorators ' +
        'before the classes that use them are defined.',
    );
  }
  const holder = metadata as Record<symbol, ClassRecord | undefined>;
  // a subclass's metadata object inherits from its superclass's
  if (!Object.hasOwn(holder, RECORD)) {
    Object.defineProperty(holder, RECORD, {
      value: { group: null, grouped: false, typePermission: null, methods: [] } satisfies ClassRecord,
      enumerable: false,
    });
  }
  return holder[RECORD]!;
}

/**
 * The record of `type` itself, or `null` if nothing on it is decorated.
 * A subclass that declares no decorators of its own has no record, even if
 * its superclass does.
 */
export function ownClassRecord(type: unknown): ClassRecord | null {
  if (typeof type !== 'function') {
    throw new IllegalArgumentError('type must be a class');
  }
  const key = (Symbol as unknown as { metadata?: symbol }).metadata;
  if (key === undefined || !Object.hasOwn(type, key)) {
    return null;
  }
  const metadata = (type as unknown as Record<symbol, unknown>)[key];
  if (typeof metadata !== 'object' || metadata === null || !Object.hasOwn(metadata, RECORD)) {
    return null;
  }
  return (metadata as Record<symbol, ClassRecord>)[RECORD] ?? null;
}

export function recordGuarded(guarded: object, record: MethodRecord): void {
  GUARDED.set(guarded, record);
}

export function guardedRecordOf(method: unknown): MethodRecord | null {
  return (typeof method === 'function' && GUARDED.get(method)) || null;
}

/**
 * Joins a `@PermGroup` value with a `@Perm` value: `("users", "create")`
 * becomes `"users.create"`. A `null` or blank group leaves `value`
 * unchanged.
 */
export function combine(groupPrefix: string | null | undefined, value: string): string {
  if (typeof value !== 'string') {
    throw new IllegalArgumentError('value must be a string');
  }
  if (groupPrefix === null || groupPrefix === undefined || isBlank(groupPrefix)) {
    return value;
  }
  return `${groupPrefix}.${value}`;
}

/** The node a `@Perm` method requires: its value under its declaring class's group. */
export function nodeOf(record: MethodRecord): string {
  const node = combine(record.owner.group, record.value);
  validateNode(node);
  return node;
}
