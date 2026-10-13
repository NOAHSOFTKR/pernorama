import { IllegalArgumentError } from '../error/errors.js';
import { PermissionNode } from '../permission/permission-node.js';
import { combine, guardedRecordOf, nodeOf, ownClassRecord } from './metadata.js';

/**
 * Turns what `@Perm` and `@PermGroup` declared into a permission node.
 * The single place that does, so the rule only exists once: the guard
 * installed by `@Perm` and {@link PermissionRegistry} both go through it.
 *
 * ## Resolution rule
 * - A method without `@Perm` requires no permission.
 * - A method with `@Perm` combines it with the `@PermGroup` of **the class
 *   that declares the method**, if any, joined with `"."`.
 * - A method inherited without being overridden keeps the node of the
 *   class that declared it; a subclass's own `@PermGroup` does not apply.
 * - **An overriding method does not inherit the `@Perm` of the method it
 *   overrides**, as in Java. If an override should still require a
 *   permission, declare `@Perm` on it again.
 */
export const PermissionAnnotationResolver = {
  /**
   * The permission node required to call `method` — a function as it sits
   * on a class or prototype after decoration — or `null` if it was not
   * guarded with `@Perm`.
   *
   * A method that another decorator wrapped *after* `@Perm` is no longer
   * the guarded function and resolves to `null` here, though calling it
   * still goes through the guard; {@link PermissionRegistry} does not have
   * this limitation.
   */
  resolve(method: unknown): string | null {
    const record = guardedRecordOf(method);
    return record === null ? null : nodeOf(record);
  },

  /**
   * Joins a `@PermGroup` value with a `@Perm` value: `("users", "create")`
   * becomes `"users.create"`. A `null` or blank group leaves `value`
   * unchanged.
   */
  combine(groupPrefix: string | null | undefined, value: string): string {
    return combine(groupPrefix, value);
  },
} as const;

/**
 * Collects the permission nodes an application declares, as queryable
 * metadata: it does not itself grant or check anything.
 *
 * {@link register} reads what `@Perm` and `@PermGroup` recorded on a
 * class. There is nothing to scan in JavaScript — no classpath, no
 * annotations on arbitrary classes — so only classes passed to it are
 * registered, and only what was declared through decorators made by
 * `createPermissionDecorators`. Nodes used only through `Permission.check`
 * can be added with {@link registerNode}.
 *
 * Only methods declared directly on the registered class are considered;
 * inherited methods are not. Registering the same class or node twice is
 * expected and safe: a node is registered once.
 */
export class PermissionRegistry {
  readonly #nodes = new Map<string, PermissionNode>();

  /**
   * Registers every permission node declared on `type`: its class-level
   * `@Perm`, then its `@Perm` methods — static and private ones
   * included — each under the class's `@PermGroup`.
   *
   * @returns the nodes found on `type`, without duplicates (including
   *          ones that were already registered before this call)
   * @throws IllegalArgumentError if `type` is not a class
   */
  register(type: abstract new (...args: never[]) => unknown): readonly PermissionNode[] {
    const record = ownClassRecord(type);
    const found = new Map<string, PermissionNode>();
    if (record !== null) {
      if (record.typePermission !== null) {
        const node = this.registerNode(combine(record.group, record.typePermission));
        found.set(node.name, node);
      }
      for (const method of record.methods) {
        const node = this.registerNode(nodeOf(method));
        found.set(node.name, node);
      }
    }
    return Object.freeze([...found.values()]);
  }

  /**
   * Registers one node by name, for permissions that are checked without
   * a decorator.
   *
   * @throws InvalidPermissionException if `node` is not a valid node
   */
  registerNode(node: string | PermissionNode): PermissionNode {
    const parsed = node instanceof PermissionNode ? node : PermissionNode.of(node);
    const known = this.#nodes.get(parsed.name);
    if (known !== undefined) {
      return known;
    }
    this.#nodes.set(parsed.name, parsed);
    return parsed;
  }

  /**
   * Looks up a previously registered node by its full dotted name.
   *
   * @throws IllegalArgumentError if no such node is registered
   */
  get(node: string): PermissionNode {
    const found = this.#nodes.get(node);
    if (found === undefined) {
      throw new IllegalArgumentError(`Unknown permission node: '${String(node)}'`);
    }
    return found;
  }

  /** Returns `true` if a node with the given name is registered. */
  contains(node: string): boolean {
    return this.#nodes.has(node);
  }

  /**
   * Returns `true` if `node` is both a syntactically valid permission node
   * and currently registered. Never throws for a malformed input.
   */
  validate(node: unknown): boolean {
    return PermissionNode.isValid(node) && this.contains(node);
  }

  /** All permission nodes registered so far, in registration order. */
  all(): readonly PermissionNode[] {
    return Object.freeze([...this.#nodes.values()]);
  }
}
