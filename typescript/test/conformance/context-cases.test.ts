// spec/context-cases.json: context validity, ContextPolicy, and subjects holding grants.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { ContextPolicy, MemoryPermissionSubject, PermissionGrant, Pernorama } from '../../src/index.js';
import { assertCheck, assertExplanation, assertFails, expectKeys, grantOf, load } from './harness.js';

describe('spec/context-cases.json', () => {
  const spec = load('context-cases.json');
  expectKeys('context-cases', spec, ['specVersion', 'description', 'contexts', 'applies', 'grants', 'subjects']);

  it('contexts', () => {
    assert.ok(spec.contexts.length > 0);
    for (const { value, valid } of spec.contexts) {
      const what = JSON.stringify(value);
      assert.equal(PermissionGrant.isValidContext(value), valid, `isValidContext(${what})`);
      if (valid) {
        assert.equal(PermissionGrant.requireValidContext(value), value);
        assert.equal(new PermissionGrant('a.b', value).context, value);
        assert.equal(new PermissionGrant('a.b', value).hasContext, value !== null);
      } else {
        assertFails('ILLEGAL_ARGUMENT', `requireValidContext(${what})`, () => PermissionGrant.requireValidContext(value));
      }
    }
  });

  it('applies', () => {
    assert.ok(spec.applies.length > 0);
    for (const c of spec.applies) {
      const policy = ContextPolicy.valueOf(c.policy);
      const what = `${c.policy}.applies(${JSON.stringify(c.granted)}, ${JSON.stringify(c.requested)})`;
      if ('error' in c) {
        assertFails(c.error, what, () => policy.applies(c.granted, c.requested));
      } else {
        assert.equal(policy.applies(c.granted, c.requested), c.applies, what);
      }
    }
  });

  it('grants', () => {
    assert.ok(spec.grants.length > 0);
    for (const c of spec.grants) {
      const what = `PermissionGrant(${JSON.stringify(c.rule)}, ${JSON.stringify(c.context)})`;
      if ('error' in c) {
        assertFails(c.error, what, () => new PermissionGrant(c.rule, c.context));
        assertFails(c.error, `grant ${what}`, () => new MemoryPermissionSubject().grant(c.rule, c.context));
        assertFails(c.error, `revoke ${what}`, () => new MemoryPermissionSubject().revoke(c.rule, c.context));
      } else {
        const grant = new PermissionGrant(c.rule, c.context);
        assert.equal(grant.rule, c.rule);
        assert.equal(grant.context, c.context);
        assert.equal(grant.toString(), c.text, what);
      }
    }
  });

  describe('subjects', () => {
    assert.ok(spec.subjects.length > 0);
    for (const c of spec.subjects) {
      it(c.name, () => {
        expectKeys(c.name, c, ['name', 'policy', 'grants', 'revoke', 'checks']);
        const policy = ContextPolicy.valueOf(c.policy);
        const subject = Pernorama.builder().contextPolicy(policy).build().newSubject();
        for (const grant of c.grants) {
          subject.grant(grantOf(grant).rule, grantOf(grant).context);
        }
        for (const grant of c.revoke ?? []) {
          subject.revoke(grantOf(grant).rule, grantOf(grant).context);
        }
        assert.equal(subject.contextPolicy, policy);

        for (const check of c.checks) {
          const context: string | null = check.context ?? null;
          const what = `${c.name}: ${JSON.stringify(check.node)} @ ${JSON.stringify(context)}`;
          assertCheck(subject, check, new Map(), what);

          // the policy over the same grants is the same evaluation
          const grants = subject.grants();
          if ('error' in check) {
            assertFails(check.error, `${what}: permits`, () => policy.permits(grants, check.node, context));
            assertFails(check.error, `${what}: policy.explain`, () => policy.explain(grants, check.node, context));
          } else {
            assert.equal(policy.permits(grants, check.node, context), check.allowed, `${what}: permits`);
            assertExplanation(policy.explain(grants, check.node, context), check, check.allowed, new Map(), what);
          }
        }
      });
    }
  });
});
