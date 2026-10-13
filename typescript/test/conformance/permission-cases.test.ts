// spec/permission-cases.json: node and rule syntax, single-rule matching, rule-set precedence.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { MemoryPermissionSubject, PermissionGrant, PermissionNode, PermissionResolver, Role } from '../../src/index.js';
import { assertExplanation, assertFails, expectKeys, load } from './harness.js';

describe('spec/permission-cases.json', () => {
  const spec = load('permission-cases.json');
  expectKeys('permission-cases', spec, [
    'specVersion', 'description', 'nodes', 'rules', 'nodeRelations', 'ruleMatching', 'ruleSets',
  ]);

  it('nodes', () => {
    assert.ok(spec.nodes.length > 0);
    for (const { value, valid } of spec.nodes) {
      assert.equal(PermissionNode.isValid(value), valid, `PermissionNode.isValid(${JSON.stringify(value)})`);
      if (valid) {
        assert.equal(PermissionNode.of(value).name, value);
        assert.equal(PermissionNode.of(value).toString(), value);
      } else {
        assertFails('INVALID_PERMISSION', `PermissionNode.of(${JSON.stringify(value)})`, () => PermissionNode.of(value));
      }
    }
  });

  it('rules', () => {
    assert.ok(spec.rules.length > 0);
    for (const { value, valid } of spec.rules) {
      const what = JSON.stringify(value);
      assert.equal(PermissionResolver.isValidPattern(value), valid, `isValidPattern(${what})`);
      const subject = new MemoryPermissionSubject();
      if (valid) {
        new PermissionGrant(value, null);
        subject.grant(value);
        subject.revoke(value);
        Role.builder('r').permission(value).build();
      } else {
        assertFails('INVALID_PERMISSION', `new PermissionGrant(${what})`, () => new PermissionGrant(value, null));
        assertFails('INVALID_PERMISSION', `grant(${what})`, () => subject.grant(value));
        assertFails('INVALID_PERMISSION', `revoke(${what})`, () => subject.revoke(value));
        assertFails('INVALID_PERMISSION', `Role.permission(${what})`, () => Role.builder('r').permission(value));
      }
    }
  });

  it('nodeRelations', () => {
    assert.ok(spec.nodeRelations.length > 0);
    for (const relation of spec.nodeRelations) {
      const node = PermissionNode.of(relation.node);
      assert.deepEqual([...node.segments], relation.segments);
      assert.equal(node.parent()?.name ?? null, relation.parent, `parent of ${relation.node}`);
      for (const { other, expected } of relation.childOf) {
        assert.equal(node.isChildOf(other), expected, `${relation.node} isChildOf ${other}`);
        assert.equal(node.isChildOf(PermissionNode.of(other)), expected);
      }
    }
  });

  it('ruleMatching', () => {
    assert.ok(spec.ruleMatching.length > 0);
    for (const c of spec.ruleMatching) {
      const what = `${JSON.stringify(c.rule)} vs ${JSON.stringify(c.node)}`;
      if ('error' in c) {
        assertFails(c.error, `matches ${what}`, () => PermissionResolver.matches(c.rule, c.node));
        assertFails(c.error, `denies ${what}`, () => PermissionResolver.denies(c.rule, c.node));
      } else {
        assert.equal(PermissionResolver.matches(c.rule, c.node), c.matches, `matches ${what}`);
        assert.equal(PermissionResolver.denies(c.rule, c.node), c.denies, `denies ${what}`);
        assert.equal(PermissionResolver.matches(c.rule, PermissionNode.of(c.node)), c.matches);
        assert.equal(PermissionResolver.denies(c.rule, PermissionNode.of(c.node)), c.denies);
      }
    }
  });

  describe('ruleSets', () => {
    assert.ok(spec.ruleSets.length > 0);
    for (const set of spec.ruleSets) {
      it(set.name, () => {
        for (const check of set.checks) {
          const what = `${set.name}: ${JSON.stringify(check.node)}`;
          if ('error' in check) {
            assertFails(check.error, `${what}: decide`, () => PermissionResolver.decide(set.rules, check.node));
            assertFails(check.error, `${what}: matchesAny`, () => PermissionResolver.matchesAny(set.rules, check.node));
            assertFails(check.error, `${what}: explain`, () => PermissionResolver.explain(set.rules, check.node));
            continue;
          }
          const allowed = check.decision === 'PERMITTED';
          assert.equal(PermissionResolver.decide(set.rules, check.node), check.decision, `${what}: decide`);
          assert.equal(PermissionResolver.matchesAny(set.rules, check.node), allowed, `${what}: matchesAny`);
          assertExplanation(PermissionResolver.explain(set.rules, check.node), check, allowed, new Map(), what);

          // a role built from the same rules decides the same way
          const builder = Role.builder('r');
          for (const rule of set.rules) {
            builder.permission(rule);
          }
          const role = builder.build();
          assert.equal(role.permissions.hasPermission(check.node), allowed, `${what}: role permits`);
          assert.equal(role.denies(check.node), check.decision === 'DENIED', `${what}: role denies`);
        }
      });
    }
  });
});
