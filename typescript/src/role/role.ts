import {
  IllegalArgumentError,
  IllegalStateError,
  InvalidPermissionException,
  UnsupportedOperationError,
} from '../error/errors.js';
import { Decision } from '../permission/decision.js';
import type { PermissionExplanation } from '../permission/permission-explanation.js';
import { PermissionGrant } from '../permission/permission-grant.js';
import { PermissionResolver } from '../permission/permission-resolver.js';
import { isValidPattern, validateNode } from '../permission/syntax.js';
import {
  checkSubject,
  explainSubject,
  isPermissionSubject,
  type PermissionSubject,
} from '../subject/permission-subject.js';
import { RoleGroup } from './role-group.js';
import { requireValidId } from './role-ids.js';

/**
 * A named, assignable bundle of permissions, optionally belonging to a
 * {@link RoleGroup}:
 *
 * ```ts
 * const pro = Role.builder('plan_pro')
 *   .group(plan)
 *   .permission('app.use')
 *   .permission('app.plan.pro')
 *   .build();
 * ```
 *
 * A role is not itself a `PermissionSubject` — a subject is whoever
 * permissions are checked against (a user, a JWT principal, a Discord
 * member), and a role is only one thing such a subject can draw
 * permissions from. What a role permits is answered by {@link permissions},
 * which uses the same rules, wildcards and deny semantics as the rest of
 * Pernorama.
 *
 * ## Where the permissions come from
 * A role is backed either by the rules passed to
 * `RoleBuilder.permission`, which are evaluated with
 * `PermissionResolver.matchesAny`, or by an existing subject passed to
 * `RoleBuilder.permissions` — for example one loaded from your database.
 * Not both.
 *
 * ## Contexts
 * A role carries no context of its own: its rules are the same wherever it
 * is held, and *where* it is held is a property of the assignment —
 * `RoleAssignments.assign(target, role, context)`. `RoleAssignments`
 * therefore always asks a role without a context. For a role built from
 * rules, {@link permissions} answers only checks without a context, and is
 * `false` for a check in one; a role backed by a subject is asked for that
 * subject's grants without a context.
 *
 * ## Identity
 * A role is identified by its {@link id}: two roles with the same id are
 * {@link equals equal}, whatever their permissions or group. Assignments
 * are stored and compared by role, so give each distinct role its own id.
 *
 * ## Definitions do not change under an assignment
 * A store keeps the `Role` instance it was given. Building a new role with
 * the same id but different rules or a different group does not update
 * targets that already hold it: assigning it is `NO_CHANGE`, and those
 * targets keep the old definition. To change what a role permits without
 * reassigning it, back the role by a subject you update, or implement a
 * store that stores role ids and resolves them against your current
 * definitions when it reads.
 */
export class Role {
  /** The id identifying this role. */
  readonly id: string;
  /** The group this role belongs to, or `null` for none. */
  readonly group: RoleGroup | null;
  /**
   * What this role permits. For a role built from rules this is a
   * read-only subject whose `grant`/`revoke` throw
   * `UnsupportedOperationError`; for a role built from a subject it is
   * that subject.
   */
  readonly permissions: PermissionSubject;
  readonly #rules: ReadonlySet<string> | null;

  private constructor(
    id: string,
    group: RoleGroup | null,
    rules: ReadonlySet<string> | null,
    permissions: PermissionSubject,
  ) {
    this.id = id;
    this.group = group;
    this.#rules = rules;
    this.permissions = permissions;
    Object.freeze(this);
  }

  /**
   * Starts building a role with the given id.
   *
   * @throws IllegalArgumentError if `id` is blank, or has leading or
   *         trailing whitespace
   */
  static builder(id: string): RoleBuilder {
    return new RoleBuilder(requireValidId(id, 'role id'), (group, rules, source) => {
      if (source !== null) {
        return new Role(id, group, null, source);
      }
      const copy: ReadonlySet<string> = new Set(rules);
      return new Role(id, group, copy, new RuleSubject(id, copy));
    });
  }

  /**
   * Returns `true` if this role **explicitly denies** `node`: the rule
   * that decides the node among this role's own rules is a deny rule. That
   * is different from not permitting it — a node no rule covers is neither
   * permitted nor denied.
   *
   * Only a role built from rules can tell the two apart. A role backed by
   * a subject is only asked whether it permits, so it never reports a
   * denial.
   *
   * @throws InvalidPermissionException if `node` is not a valid node
   */
  denies(node: string): boolean {
    if (this.#rules === null) {
      validateNode(node);
      return false;
    }
    return PermissionResolver.decide(this.#rules, node) === Decision.DENIED;
  }

  /**
   * Whether this role permits `node`, explicitly denies it, or does not
   * cover it, in one evaluation. A role backed by a subject never reports
   * `DENIED`, for the reason given in {@link denies}.
   *
   * @internal
   */
  _decide(node: string): Decision {
    if (this.#rules !== null) {
      return PermissionResolver.decide(this.#rules, node);
    }
    validateNode(node);
    return checkSubject(this.permissions, node, null) ? Decision.PERMITTED : Decision.NOT_COVERED;
  }

  /**
   * {@link _decide}'s evaluation, reporting why: for a role built from
   * rules, `PermissionResolver.explain` over them; for a role backed by a
   * subject, that subject's explanation of a check without a context — one
   * query.
   *
   * @internal
   */
  _explain(node: string): PermissionExplanation {
    if (this.#rules !== null) {
      return PermissionResolver.explain(this.#rules, node);
    }
    return explainSubject(this.permissions, node, null);
  }

  /**
   * What {@link _decide} answers, read off an explanation from
   * {@link _explain} instead of evaluating the node again. A role backed
   * by a subject is counted only by whether it permits, as in `_decide`.
   *
   * @internal
   */
  _decisionOf(explanation: PermissionExplanation): Decision {
    if (this.#rules !== null) {
      if (explanation.decision === null) {
        throw new IllegalStateError(`role '${this.id}' explained its rules without a decision`);
      }
      return explanation.decision;
    }
    return explanation.allowed ? Decision.PERMITTED : Decision.NOT_COVERED;
  }

  /** Two roles are equal if they have the same id. */
  equals(other: unknown): boolean {
    return other instanceof Role && other.id === this.id;
  }

  toString(): string {
    return this.id;
  }
}

/** Builder for {@link Role}; get one from `Role.builder`. */
export class RoleBuilder {
  readonly #id: string;
  readonly #create: (
    group: RoleGroup | null,
    rules: ReadonlySet<string>,
    source: PermissionSubject | null,
  ) => Role;
  #group: RoleGroup | null = null;
  readonly #rules = new Set<string>();
  #source: PermissionSubject | null = null;

  /** @internal */
  constructor(
    id: string,
    create: (group: RoleGroup | null, rules: ReadonlySet<string>, source: PermissionSubject | null) => Role,
  ) {
    this.#id = id;
    this.#create = create;
  }

  /** Puts the role in `group`. */
  group(group: RoleGroup): this {
    if (!(group instanceof RoleGroup)) {
      throw new IllegalArgumentError('group must be a RoleGroup');
    }
    this.#group = group;
    return this;
  }

  /**
   * Adds a permission rule — a node, a wildcard, or either prefixed with
   * `-` to deny — exactly as `PermissionSubject.grant` accepts it.
   *
   * @throws InvalidPermissionException if `rule` is not a valid rule
   */
  permission(rule: string): this {
    if (!isValidPattern(rule)) {
      throw new InvalidPermissionException(rule);
    }
    this.#rules.add(rule);
    return this;
  }

  /**
   * Backs the role by an existing subject instead of by rules, e.g. one
   * loaded from your own storage.
   */
  permissions(source: PermissionSubject): this {
    if (!isPermissionSubject(source)) {
      throw new IllegalArgumentError('source must be a PermissionSubject');
    }
    this.#source = source;
    return this;
  }

  /**
   * Builds the role.
   *
   * @throws IllegalStateError if both rules and a backing subject were given
   */
  build(): Role {
    if (this.#source !== null && this.#rules.size > 0) {
      throw new IllegalStateError(
        `role '${this.#id}' has both rules and a backing subject; use one or the other`,
      );
    }
    return this.#create(this.#group, this.#rules, this.#source);
  }
}

/** The read-only subject behind a role built from rules. */
class RuleSubject implements PermissionSubject {
  readonly #roleId: string;
  readonly #rules: ReadonlySet<string>;

  constructor(roleId: string, rules: ReadonlySet<string>) {
    this.#roleId = roleId;
    this.#rules = rules;
  }

  /**
   * A role's rules carry no context, so they answer only a check without
   * one; a check in a context is `false`, under any `ContextPolicy`. Hold
   * the role in a context through `RoleAssignments` instead.
   */
  hasPermission(node: string, context?: string | null): boolean {
    const requested = PermissionGrant.requireValidContext(context);
    const permitted = PermissionResolver.matchesAny(this.#rules, node);
    return requested === null && permitted;
  }

  grant(): never {
    throw new UnsupportedOperationError(`role '${this.#roleId}' is immutable; build a new role instead`);
  }

  revoke(): never {
    throw new UnsupportedOperationError(`role '${this.#roleId}' is immutable; build a new role instead`);
  }

  toString(): string {
    return `Role[${this.#roleId}][${[...this.#rules].join(', ')}]`;
  }
}
