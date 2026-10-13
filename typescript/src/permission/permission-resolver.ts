import { Decision } from './decision.js';
import { PermissionExplanation, type RankedGrant } from './permission-explanation.js';
import { PermissionGrant } from './permission-grant.js';
import { PermissionNode } from './permission-node.js';
import {
  decisionOf,
  isDeny,
  isValidPattern,
  NOT_COVERING,
  rank,
  specificity,
  validateNode,
  validateRule,
} from './syntax.js';

/**
 * The single component responsible for permission node/rule syntax
 * validation and for deciding whether a set of granted permission rules
 * permits a required permission node.
 *
 * ## Rules
 * A rule is either an **allow** rule or a **deny** rule:
 *
 * - `"users.create"` allows exactly that node.
 * - `"users.*"` allows `"users"` and everything under it. A wildcard
 *   segment is only meaningful as the final segment of a rule;
 *   `"users.*.read"` is not a valid rule.
 * - `"*"` allows every permission.
 * - A leading `-` makes the same forms deny instead of allow:
 *   `"-users.delete"`, `"-users.*"`, `"-*"`.
 *
 * ## Which rule wins
 * {@link PermissionResolver.matchesAny} evaluates a whole set of rules
 * against one required node: **the most specific rule that covers the node
 * decides**, and a deny rule wins a tie. Specificity is, in order:
 *
 * 1. an exact rule (`"users.delete"`) beats a wildcard rule that also
 *    covers the node;
 * 2. between two wildcard rules, the one with more segments before the `*`
 *    wins (`"users.profile.*"` beats `"users.*"`, which beats `"*"`).
 *
 * So `["users.*", "-users.delete"]` permits `users.create` but not
 * `users.delete`, and `["-users.*", "users.read"]` permits `users.read`
 * and nothing else under `users`. A node that no rule covers is not
 * permitted.
 *
 * An exact rule covers exactly its own node, and that holds for deny rules
 * too: `"-users.delete"` does not deny `"users.delete.hard"`, which the
 * surrounding `"users.*"` still permits. Deny the subtree with
 * `"-users.delete.*"`, which covers `users.delete` and everything under it.
 *
 * ## Node syntax
 * Because a leading `-` marks a deny rule, a permission node itself may
 * never start with `-`; the character remains legal anywhere else
 * (`"users.soft-delete"`).
 */
export const PermissionResolver = {
  /**
   * Returns `true` if the given value is a syntactically valid permission
   * rule: a non-blank string of dot-separated segments made of letters,
   * digits, `_` or `-`, optionally ending in a single trailing `*` segment
   * (or being `"*"` on its own), and optionally prefixed with a single `-`
   * to deny rather than allow.
   */
  isValidPattern(pattern: unknown): pattern is string {
    return isValidPattern(pattern);
  },

  /**
   * Returns `true` if `pattern` is an **allow** rule that covers the
   * `required` permission node. A deny rule never allows anything, so this
   * returns `false` for one; use {@link PermissionResolver.denies} to test
   * a deny rule, or {@link PermissionResolver.matchesAny} to evaluate a
   * whole rule set.
   *
   * @throws InvalidPermissionException if `pattern` is not a valid
   *         permission rule, or `required` is not a valid permission node
   */
  matches(pattern: string, required: string | PermissionNode): boolean {
    const node = nodeName(required);
    validateRule(pattern);
    validateNode(node);
    return !isDeny(pattern) && specificity(pattern, node) >= 0;
  },

  /**
   * Returns `true` if `pattern` is a **deny** rule that covers the
   * `required` permission node. The mirror image of
   * {@link PermissionResolver.matches}: an allow rule never denies
   * anything, so this returns `false` for one.
   *
   * @throws InvalidPermissionException if `pattern` is not a valid
   *         permission rule, or `required` is not a valid permission node
   */
  denies(pattern: string, required: string | PermissionNode): boolean {
    const node = nodeName(required);
    validateRule(pattern);
    validateNode(node);
    return isDeny(pattern) && specificity(pattern.substring(1), node) >= 0;
  },

  /**
   * Returns `true` if the rules in `patterns` permit the `required`
   * permission node: the most specific covering rule decides, a deny rule
   * wins a tie, and a node no rule covers is not permitted.
   *
   * Every rule is examined, so an invalid rule anywhere in `patterns` is
   * reported even when an earlier rule already covers the node. `required`
   * is validated as a node, which is what keeps a caller from asking about
   * something that is not one — `"-users.read"` or `"users.*"` — and
   * stepping around a deny rule that way.
   *
   * @throws InvalidPermissionException if any rule in `patterns` is not a
   *         valid permission rule, or `required` is not a valid node
   */
  matchesAny(patterns: Iterable<string>, required: string): boolean {
    return decideRules(patterns, required, null) === Decision.PERMITTED;
  },

  /**
   * The three-way answer behind {@link PermissionResolver.matchesAny}:
   * `PERMITTED` or `DENIED` by the rule that decides the node, or
   * `NOT_COVERED` if no rule covers it. Telling the last two apart is what
   * lets `ContextPolicy` fall back from one set of rules to the next only
   * when the first says nothing, and what lets a role report an explicit
   * denial.
   *
   * @throws InvalidPermissionException if any rule in `patterns` is not a
   *         valid permission rule, or `required` is not a valid node
   */
  decide(patterns: Iterable<string>, required: string): Decision {
    return decideRules(patterns, required, null);
  },

  /**
   * {@link PermissionResolver.decide}, also reporting which rules covered
   * `required` and which of them decided it. The rules carry no context,
   * so the explanation has no context, no context policy and no layers;
   * every match is a {@link PermissionGrant} without a context.
   *
   * @throws InvalidPermissionException if any rule in `patterns` is not a
   *         valid permission rule, or `required` is not a valid node
   */
  explain(patterns: Iterable<string>, required: string): PermissionExplanation {
    const covering: RankedGrant[] = [];
    const decision = decideRules(patterns, required, covering);
    return PermissionExplanation._ofRules(required, null, decision, null, covering);
  },
} as const;

/**
 * The one evaluation behind `decide` and `explain`: adds every covering
 * rule to `covering` unless it is `null`, which is the plain check.
 */
function decideRules(patterns: Iterable<string>, required: string, covering: RankedGrant[] | null): Decision {
  validateNode(required);

  let best = NOT_COVERING;
  for (const pattern of patterns) {
    validateRule(pattern);
    const ranked = rank(pattern, required);
    best = Math.max(best, ranked);
    if (covering !== null && ranked !== NOT_COVERING) {
      covering.push({ grant: new PermissionGrant(pattern, null), fallback: false, rank: ranked });
    }
  }
  return decisionOf(best);
}

function nodeName(required: string | PermissionNode): string {
  return required instanceof PermissionNode ? required.name : required;
}
