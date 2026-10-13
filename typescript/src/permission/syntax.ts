// The one definition of permission syntax and rule ranking. PermissionNode,
// PermissionGrant, PermissionResolver and ContextPolicy all build on it, so
// they can never disagree; it is not part of the public API.

import { InvalidPermissionException } from '../error/errors.js';
import { Decision } from './decision.js';

const SEGMENT = /^[A-Za-z0-9_-]+$/;
const SEPARATOR = '.';
const WILDCARD = '*';
const WILDCARD_SUFFIX = '.*';
const DENY_PREFIX = '-';

/** {@link rank}: the rule does not cover the node. */
export const NOT_COVERING = -1;

/** One or more letters, digits, `_` or `-`. Does not accept `"*"`. */
function isValidSegment(segment: string): boolean {
  return SEGMENT.test(segment);
}

/**
 * Whether `value` starts with the deny prefix `-`, i.e. it is meant as a
 * deny rule rather than a node. Says nothing about the rest of it.
 */
export function isDeny(value: string): boolean {
  return value.length > 0 && value.charAt(0) === DENY_PREFIX;
}

/**
 * Splits and validates a node in a single pass, or returns `null` if
 * `value` is not a string, is blank, is a deny rule, or contains an empty
 * or invalid segment.
 */
export function parseNodeSegments(value: unknown): string[] | null {
  if (typeof value !== 'string' || value.length === 0 || isDeny(value)) {
    return null;
  }
  const segments = value.split(SEPARATOR);
  for (const segment of segments) {
    if (!isValidSegment(segment)) {
      return null;
    }
  }
  return segments;
}

export function isValidNode(value: unknown): value is string {
  return parseNodeSegments(value) !== null;
}

export function isValidPattern(pattern: unknown): pattern is string {
  if (typeof pattern !== 'string' || pattern.length === 0) {
    return false;
  }
  return isValidAllowPattern(isDeny(pattern) ? pattern.substring(1) : pattern);
}

export function validateRule(pattern: unknown): asserts pattern is string {
  if (!isValidPattern(pattern)) {
    throw new InvalidPermissionException(pattern);
  }
}

export function validateNode(required: unknown): asserts required is string {
  if (!isValidNode(required)) {
    throw new InvalidPermissionException(required);
  }
}

/**
 * How strongly `rule` — a valid rule, deny prefix included — speaks for
 * `required`, a valid node, or {@link NOT_COVERING}. The highest rank among
 * a set of rules decides the node: it orders rules by specificity, and a
 * deny rule ranks just above an allow rule of the same specificity, so a
 * deny wins a tie. An odd rank is a deny.
 */
export function rank(rule: string, required: string): number {
  const deny = isDeny(rule);
  const score = specificity(deny ? rule.substring(1) : rule, required);
  if (score < 0) {
    return NOT_COVERING;
  }
  return 2 * score + (deny ? 1 : 0);
}

/** The {@link Decision} of a set of rules whose highest {@link rank} is `best`. */
export function decisionOf(best: number): Decision {
  if (best === NOT_COVERING) {
    return Decision.NOT_COVERED;
  }
  return best % 2 === 0 ? Decision.PERMITTED : Decision.DENIED;
}

/**
 * Validates a rule with any deny prefix already stripped: the same syntax
 * an allow rule uses, which is also what a deny rule has to wrap. A second
 * leading `-` is rejected here rather than read as part of a segment, so
 * `"--users"` is not a rule.
 */
function isValidAllowPattern(pattern: string): boolean {
  if (pattern.length === 0 || isDeny(pattern)) {
    return false;
  }
  const segments = pattern.split(SEPARATOR);
  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i]!;
    if (segment === WILDCARD) {
      if (i !== segments.length - 1) {
        return false;
      }
      continue;
    }
    if (!isValidSegment(segment)) {
      return false;
    }
  }
  return true;
}

/**
 * How specific `rule` — a valid rule with any deny prefix already
 * stripped — is for `required`, or `-1` if it does not cover it at all.
 * Higher wins; an exact rule scores above every wildcard rule that covers
 * the same node, and a longer wildcard prefix scores above a shorter one.
 */
export function specificity(rule: string, required: string): number {
  if (rule === WILDCARD) {
    return 0;
  }
  if (rule === required) {
    return 2 * segmentCount(rule) + 1;
  }
  if (rule.endsWith(WILDCARD_SUFFIX)) {
    const prefix = rule.substring(0, rule.length - WILDCARD_SUFFIX.length);
    if (required === prefix || required.startsWith(prefix + SEPARATOR)) {
      return 2 * segmentCount(prefix);
    }
  }
  return -1;
}

function segmentCount(value: string): number {
  let count = 1;
  for (let i = 0; i < value.length; i++) {
    if (value.charAt(i) === SEPARATOR) {
      count++;
    }
  }
  return count;
}
