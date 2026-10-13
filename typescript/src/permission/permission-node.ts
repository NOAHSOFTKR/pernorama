import { InvalidPermissionException } from '../error/errors.js';
import { parseNodeSegments } from './syntax.js';

const SEPARATOR = '.';

/**
 * An immutable, dot-separated permission identifier such as
 * `"users.create"`.
 *
 * A `PermissionNode` always represents a concrete node; it does not carry
 * wildcard segments, and it never starts with `-`, which
 * `PermissionResolver` reads as the deny-rule marker.
 */
export class PermissionNode {
  /** The full dotted node name, e.g. `"users.create"`. */
  readonly name: string;
  /** The individual dot-separated segments, e.g. `["users", "create"]`. */
  readonly segments: readonly string[];

  private constructor(segments: readonly string[]) {
    this.segments = Object.freeze([...segments]);
    this.name = segments.join(SEPARATOR);
    Object.freeze(this);
  }

  /**
   * Parses a dot-separated string into a `PermissionNode`. Wildcards
   * (`"*"`, `"users.*"`) and deny rules (`"-users.delete"`) are not valid
   * nodes; use `PermissionResolver.isValidPattern` to validate a grantable
   * rule instead.
   *
   * @throws InvalidPermissionException if the value is not a string, is
   *         blank, starts with `-`, or contains an empty or invalid segment
   */
  static of(value: string): PermissionNode {
    const segments = parseNodeSegments(value);
    if (segments === null) {
      throw new InvalidPermissionException(value);
    }
    return new PermissionNode(segments);
  }

  /**
   * Returns `true` if `value` would be accepted by {@link PermissionNode.of},
   * without throwing for invalid input — including input that is not a
   * string at all.
   */
  static isValid(value: unknown): value is string {
    return parseNodeSegments(value) !== null;
  }

  /**
   * The parent node, e.g. the parent of `"users.create"` is `"users"`.
   * A top-level node such as `"users"` has none.
   */
  parent(): PermissionNode | null {
    if (this.segments.length <= 1) {
      return null;
    }
    return new PermissionNode(this.segments.slice(0, -1));
  }

  /**
   * Returns `true` if this node is a descendant of `other`, i.e. `other`'s
   * segments are a proper prefix of this node's segments. A node is never
   * a child of itself.
   */
  isChildOf(other: PermissionNode | string): boolean {
    const parent = typeof other === 'string' ? PermissionNode.of(other) : other;
    if (parent.segments.length >= this.segments.length) {
      return false;
    }
    return parent.segments.every((segment, i) => segment === this.segments[i]);
  }

  /** Two nodes are equal if they have the same name. */
  equals(other: unknown): boolean {
    return other instanceof PermissionNode && other.name === this.name;
  }

  toString(): string {
    return this.name;
  }

  toJSON(): string {
    return this.name;
  }
}
