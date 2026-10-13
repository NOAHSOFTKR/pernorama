// Shared plumbing for running the language-neutral fixtures in /spec
// against the TypeScript implementation. The Java suite
// (pernorama.conformance.ConformanceTest) runs the very same files; the
// format is described in spec/README.md.

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  CompositePermissionSubject,
  ContextPolicy,
  IllegalArgumentError,
  IllegalStateError,
  InvalidPermissionException,
  MemoryPermissionSubject,
  Permission,
  PermissionDeniedException,
  type PermissionExplanation,
  type PermissionSubject,
  RoleAssignment,
  UnsupportedOperationError,
} from '../../src/index.js';

export type Json = any; // eslint-disable-line -- fixtures are untyped by design

/** The repository's spec/ directory: PERNORAMA_SPEC_DIR, or the nearest one above this file. */
function specDir(): string {
  const configured = process.env['PERNORAMA_SPEC_DIR'];
  if (configured !== undefined && configured !== '') {
    return configured;
  }
  let dir = dirname(fileURLToPath(import.meta.url));
  for (;;) {
    const candidate = join(dir, 'spec');
    if (existsSync(join(candidate, 'permission-cases.json'))) {
      return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) {
      throw new Error('cannot find the spec/ directory; set PERNORAMA_SPEC_DIR');
    }
    dir = parent;
  }
}

const SUPPORTED_SPEC_VERSION = 1;

export function load(name: string): Json {
  const spec = JSON.parse(readFileSync(join(specDir(), name), 'utf8'));
  assert.equal(spec.specVersion, SUPPORTED_SPEC_VERSION, `${name}: unsupported specVersion`);
  return spec;
}

/** Fails on a fixture key this harness does not know, so a new kind of case cannot be silently skipped. */
export function expectKeys(what: string, value: Json, allowed: readonly string[]): void {
  for (const key of Object.keys(value)) {
    assert.ok(allowed.includes(key), `${what}: unknown fixture key '${key}'`);
  }
}

function errorKind(error: unknown): string {
  if (error instanceof InvalidPermissionException) return 'INVALID_PERMISSION';
  if (error instanceof PermissionDeniedException) return 'PERMISSION_DENIED';
  if (error instanceof IllegalArgumentError) return 'ILLEGAL_ARGUMENT';
  if (error instanceof IllegalStateError) return 'ILLEGAL_STATE';
  if (error instanceof UnsupportedOperationError) return 'UNSUPPORTED_OPERATION';
  return `UNEXPECTED(${String(error)})`;
}

export function assertFails(kind: string, what: string, action: () => unknown): void {
  let result: unknown;
  try {
    result = action();
  } catch (error) {
    assert.equal(errorKind(error), kind, what);
    return;
  }
  assert.fail(`${what}: expected ${kind}, but got ${String(result)}`);
}

// ---- explanations ----------------------------------------------------------

export type Labels = Map<object, string>;

function canonical(explanation: PermissionExplanation, labels: Labels): Json {
  return {
    allowed: explanation.allowed,
    decision: explanation.decision,
    provenance: explanation.provenance,
    contextPolicy: explanation.contextPolicy?.name ?? null,
    resolutionPolicy: explanation.resolutionPolicy,
    decidingLayer: explanation.decidingLayer,
    matches: explanation.matches.map((match) => ({
      rule: match.grant.rule,
      context: match.grant.context,
      decisive: match.decisive,
      deny: match.deny,
      wildcard: match.wildcard,
    })),
    contributions: explanation.contributions.map((contribution) => ({
      source: sourceLabel(contribution.source, labels),
      decisive: contribution.decisive,
      explanation: canonical(contribution.explanation, labels),
    })),
  };
}

function sourceLabel(source: object, labels: Labels): Json {
  if (source instanceof RoleAssignment) {
    return { role: source.role.id, context: source.context };
  }
  const label = labels.get(source);
  assert.ok(label !== undefined, 'a contribution names a source the fixture did not label');
  return { subject: label };
}

/** An expected explanation with the defaults of spec/README.md filled in. */
function normalized(expected: Json, what: string): Json {
  expectKeys(`${what} explanation`, expected, [
    'allowed', 'decision', 'provenance', 'contextPolicy', 'resolutionPolicy', 'decidingLayer', 'matches', 'contributions',
  ]);
  for (const required of ['allowed', 'decision', 'provenance']) {
    assert.ok(required in expected, `${what} explanation: '${required}' is required`);
  }
  return {
    allowed: expected.allowed,
    decision: expected.decision,
    provenance: expected.provenance,
    contextPolicy: expected.contextPolicy ?? null,
    resolutionPolicy: expected.resolutionPolicy ?? null,
    decidingLayer: expected.decidingLayer ?? null,
    matches: (expected.matches ?? []).map((match: Json) => {
      expectKeys(`${what} match`, match, ['rule', 'context', 'decisive', 'deny', 'wildcard']);
      return {
        rule: match.rule,
        context: match.context ?? null,
        decisive: match.decisive ?? false,
        deny: match.deny ?? false,
        wildcard: match.wildcard ?? false,
      };
    }),
    contributions: (expected.contributions ?? []).map((contribution: Json) => {
      expectKeys(`${what} contribution`, contribution, ['source', 'decisive', 'explanation']);
      const source = contribution.source;
      return {
        source: 'role' in source ? { role: source.role, context: source.context ?? null } : { subject: source.subject },
        decisive: contribution.decisive ?? false,
        explanation: normalized(contribution.explanation, what),
      };
    }),
  };
}

export function assertExplanation(
  actual: PermissionExplanation,
  check: Json,
  allowed: boolean,
  labels: Labels,
  what: string,
): void {
  assert.equal(actual.node, check.node, `${what}: explanation node`);
  assert.equal(actual.context, check.context ?? null, `${what}: explanation context`);
  assert.equal(actual.allowed, allowed, `${what}: explanation.allowed`);
  if ('decision' in check) {
    assert.equal(actual.decision, check.decision, `${what}: explanation.decision`);
  }
  if ('explanation' in check) {
    assert.deepEqual(canonical(actual, labels), normalized(check.explanation, what), `${what}: explanation`);
    assert.equal(check.explanation.allowed, allowed, `${what}: fixture explanation contradicts 'allowed'`);
  }
}

/** Everything a fixture expects of one check against one subject. */
export function assertCheck(subject: PermissionSubject, check: Json, labels: Labels, what: string): void {
  const context: string | null = check.context ?? null;
  if ('error' in check) {
    assertFails(check.error, `${what}: hasPermission`, () => subject.hasPermission(check.node, context));
    assertFails(check.error, `${what}: explain`, () => Permission.explain(subject, check.node, context));
    assertFails(check.error, `${what}: Permission.check`, () => Permission.check(subject, check.node, context));
    assertFails(check.error, `${what}: Permission.require`, () => Permission.require(subject, check.node, context));
    return;
  }
  const allowed: boolean = check.allowed;
  assert.equal(typeof allowed, 'boolean', `${what}: fixture needs 'allowed'`);
  assert.equal(subject.hasPermission(check.node, context), allowed, `${what}: hasPermission`);
  assert.equal(Permission.check(subject, check.node, context), allowed, `${what}: Permission.check`);
  if (allowed) {
    Permission.require(subject, check.node, context);
  } else {
    try {
      Permission.require(subject, check.node, context);
      assert.fail(`${what}: Permission.require did not throw`);
    } catch (error) {
      assert.ok(error instanceof PermissionDeniedException, `${what}: Permission.require threw ${String(error)}`);
      assert.equal(error.requiredPermission, check.node);
      assert.equal(error.context, context);
      assert.equal(error.subject, subject);
    }
  }
  assertExplanation(Permission.explain(subject, check.node, context), check, allowed, labels, what);
}

// ---- subjects --------------------------------------------------------------

export function grantOf(grant: Json): { rule: string; context: string | null } {
  return typeof grant === 'string' || grant === null ? { rule: grant, context: null } : { rule: grant.rule, context: grant.context ?? null };
}

export function buildSubject(def: Json, labels: Labels): PermissionSubject {
  expectKeys('subject', def, ['label', 'kind', 'policy', 'grants', 'sources']);
  let subject: PermissionSubject;
  switch (def.kind) {
    case 'memory': {
      const memory = new MemoryPermissionSubject(ContextPolicy.valueOf(def.policy));
      for (const grant of def.grants) {
        memory.grant(grantOf(grant).rule, grantOf(grant).context);
      }
      subject = memory;
      break;
    }
    case 'opaque': {
      // a custom subject that implements only the mandatory methods
      const memory = buildSubject({ ...def, kind: 'memory', label: undefined }, new Map()) as MemoryPermissionSubject;
      subject = {
        hasPermission: (node, context) => memory.hasPermission(node, context),
        grant: (rule, context) => memory.grant(rule, context),
        revoke: (rule, context) => memory.revoke(rule, context),
      };
      break;
    }
    case 'failing':
      subject = {
        hasPermission: () => {
          throw new IllegalStateError('this source always fails');
        },
        grant: () => {
          throw new IllegalStateError('this source always fails');
        },
        revoke: () => {
          throw new IllegalStateError('this source always fails');
        },
      };
      break;
    case 'composite':
      subject = new CompositePermissionSubject(def.sources.map((source: Json) => buildSubject(source, labels)));
      break;
    default:
      assert.fail(`unknown subject kind '${def.kind}'`);
  }
  if (def.label !== undefined) {
    labels.set(subject, def.label);
  }
  return subject;
}
