// spec/role-cases.json: composite subjects, roles, groups, assignments and resolution policies.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  type CompositePermissionSubject,
  ContextPolicy,
  PermissionResolutionPolicy,
  Pernorama,
  Role,
  RoleAssignmentDecision,
  RoleAssignmentPolicy,
  type RoleAssignmentResult,
  type RoleAssignments,
  RoleGroup,
} from '../../src/index.js';
import { assertCheck, assertFails, buildSubject, expectKeys, type Json, type Labels, load } from './harness.js';

const ASSIGNMENT_POLICIES: Record<string, RoleAssignmentPolicy> = {
  REJECT: RoleAssignmentPolicy.REJECT,
  REPLACE_EXISTING: RoleAssignmentPolicy.REPLACE_EXISTING,
  REPLACE_OLDEST: RoleAssignmentPolicy.REPLACE_OLDEST,
  REPLACE_NEWEST: RoleAssignmentPolicy.REPLACE_NEWEST,
  // custom policies whose decisions break the group's limits
  BROKEN_REPLACE_NONE: { decide: () => RoleAssignmentDecision.replace([]) },
  BROKEN_REPLACE_REQUESTED: { decide: (_group, _held, requested) => RoleAssignmentDecision.replace([requested]) },
};

const RESOLUTION_POLICIES: Record<string, PermissionResolutionPolicy> = {
  ALLOW_OVERRIDES: PermissionResolutionPolicy.ALLOW_OVERRIDES,
  DENY_OVERRIDES: PermissionResolutionPolicy.DENY_OVERRIDES,
  // a custom policy: permitted if any applicable role permits, with no layering
  CUSTOM_ANY: {
    hasPermission: (assignments, node) =>
      assignments.some((assignment) => assignment.role.permissions.hasPermission(node)),
  },
};

function lookup<T>(table: Record<string, T>, name: string, what: string): T {
  const found = table[name];
  assert.ok(found !== undefined, `unknown ${what} '${name}'`);
  return found;
}

function buildGroup(def: Json): RoleGroup {
  const builder = RoleGroup.builder(def.id);
  if (def.min !== undefined) builder.minAssignments(def.min);
  if (def.max !== undefined) builder.maxAssignments(def.max);
  if (def.policy !== undefined) builder.assignmentPolicy(lookup(ASSIGNMENT_POLICIES, def.policy, 'assignment policy'));
  return builder.build();
}

function assertResult(result: RoleAssignmentResult, step: Json, role: Role, what: string): void {
  const expect = step.expect;
  expectKeys(`${what} expect`, expect, ['status', 'removed', 'current', 'reason']);
  assert.equal(result.status, expect.status, `${what}: status`);
  assert.deepEqual(result.removedRoles.map((removed) => removed.id), expect.removed, `${what}: removed`);
  assert.equal(result.currentRole?.id ?? null, expect.current, `${what}: current`);
  assert.equal(result.previousRole?.id ?? null, expect.removed[0] ?? null, `${what}: previous`);
  assert.equal(result.role, role, `${what}: role`);
  assert.equal(result.context, step.context ?? null, `${what}: context`);
  assert.equal(result.group, role.group, `${what}: group`);
  assert.equal(result.rejectionReason !== null, expect.status === 'REJECTED', `${what}: rejection reason presence`);
  if ('reason' in expect) {
    assert.equal(result.rejectionReason, expect.reason, `${what}: reason`);
  }
}

describe('spec/role-cases.json', () => {
  const spec = load('role-cases.json');
  expectKeys('role-cases', spec, [
    'specVersion', 'description', 'ids', 'groupDefinitions', 'composites', 'scenarios',
  ]);

  it('ids', () => {
    assert.ok(spec.ids.length > 0);
    for (const { value, valid } of spec.ids) {
      const what = JSON.stringify(value);
      if (valid) {
        assert.equal(Role.builder(value).build().id, value, `Role.builder(${what})`);
        assert.equal(RoleGroup.builder(value).build().id, value, `RoleGroup.builder(${what})`);
      } else {
        assertFails('ILLEGAL_ARGUMENT', `Role.builder(${what})`, () => Role.builder(value));
        assertFails('ILLEGAL_ARGUMENT', `RoleGroup.builder(${what})`, () => RoleGroup.builder(value));
      }
    }
  });

  it('groupDefinitions', () => {
    assert.ok(spec.groupDefinitions.length > 0);
    for (const def of spec.groupDefinitions) {
      expectKeys('groupDefinition', def, ['min', 'max', 'policy', 'valid', 'expectMin', 'expectMax']);
      const what = JSON.stringify(def);
      if (def.valid) {
        const group = buildGroup({ ...def, id: 'g' });
        if (def.expectMin !== undefined) assert.equal(group.minAssignments, def.expectMin, what);
        if (def.expectMax !== undefined) assert.equal(group.maxAssignments, def.expectMax, what);
      } else {
        assertFails('ILLEGAL_ARGUMENT', what, () => buildGroup({ ...def, id: 'g' }));
      }
    }
  });

  describe('composites', () => {
    assert.ok(spec.composites.length > 0);
    for (const c of spec.composites) {
      it(c.name, () => {
        expectKeys(c.name, c, ['name', 'sources', 'checks']);
        const labels: Labels = new Map();
        const composite = buildSubject({ kind: 'composite', sources: c.sources }, labels) as CompositePermissionSubject;
        assert.equal(composite.sources.length, c.sources.length);
        assertFails('UNSUPPORTED_OPERATION', `${c.name}: grant`, () => composite.grant('a.b'));
        assertFails('UNSUPPORTED_OPERATION', `${c.name}: revoke`, () => composite.revoke('a.b'));
        for (const check of c.checks) {
          assertCheck(composite, check, labels, `${c.name}: ${JSON.stringify(check.node)} @ ${JSON.stringify(check.context ?? null)}`);
        }
      });
    }
  });

  describe('scenarios', () => {
    assert.ok(spec.scenarios.length > 0);
    for (const scenario of spec.scenarios) {
      it(scenario.name, () => {
        expectKeys(scenario.name, scenario, ['name', 'contextPolicy', 'groups', 'roles', 'steps']);
        const labels: Labels = new Map();
        const groups = new Map<string, RoleGroup>();
        for (const def of scenario.groups ?? []) {
          expectKeys('group', def, ['key', 'id', 'min', 'max', 'policy']);
          groups.set(def.key ?? def.id, buildGroup(def));
        }
        const roles = new Map<string, Role>();
        for (const def of scenario.roles) {
          expectKeys('role', def, ['key', 'id', 'group', 'rules', 'subject']);
          const builder = Role.builder(def.id);
          if (def.group !== undefined) {
            const group = groups.get(def.group);
            assert.ok(group !== undefined, `unknown group '${def.group}'`);
            builder.group(group);
          }
          for (const rule of def.rules ?? []) {
            builder.permission(rule);
          }
          if (def.subject !== undefined) {
            builder.permissions(buildSubject(def.subject, labels));
          }
          roles.set(def.key ?? def.id, builder.build());
        }
        const roleOf = (key: string): Role => {
          const role = roles.get(key);
          assert.ok(role !== undefined, `unknown role '${key}'`);
          return role;
        };

        const pernorama = Pernorama.builder().contextPolicy(ContextPolicy.valueOf(scenario.contextPolicy)).build();
        const assignments: RoleAssignments<string> = pernorama.newRoleAssignments<string>();
        assert.equal(assignments.contextPolicy, pernorama.contextPolicy);

        scenario.steps.forEach((step: Json, index: number) => {
          const what = `${scenario.name}: step ${index + 1} (${step.op})`;
          const context: string | null = step.context ?? null;
          switch (step.op) {
            case 'assign':
            case 'unassign': {
              expectKeys(what, step, ['op', 'target', 'role', 'context', 'expect', 'error']);
              const role = roleOf(step.role);
              const run = (): RoleAssignmentResult =>
                step.op === 'assign'
                  ? assignments.assign(step.target, role, context)
                  : assignments.unassign(step.target, role, context);
              if ('error' in step) {
                const before = assignments.assignments(step.target);
                assertFails(step.error, what, run);
                assert.deepEqual(assignments.assignments(step.target), before, `${what}: nothing may change`);
              } else {
                assertResult(run(), step, role, what);
              }
              break;
            }
            case 'roles':
              expectKeys(what, step, ['op', 'target', 'context', 'expect', 'error']);
              if ('error' in step) {
                assertFails(step.error, what, () => assignments.roles(step.target, context));
              } else {
                assert.deepEqual(assignments.roles(step.target, context).map((role) => role.id), step.expect, what);
              }
              break;
            case 'assignments':
              expectKeys(what, step, ['op', 'target', 'expect']);
              assert.deepEqual(
                assignments.assignments(step.target).map((a) => ({ role: a.role.id, context: a.context })),
                step.expect.map((a: Json) => ({ role: a.role, context: a.context ?? null })),
                what,
              );
              break;
            case 'check': {
              expectKeys(what, step, [
                'op', 'target', 'resolution', 'node', 'context', 'allowed', 'decision', 'explanation', 'error',
              ]);
              const policy = lookup(RESOLUTION_POLICIES, step.resolution ?? 'ALLOW_OVERRIDES', 'resolution policy');
              const subject = assignments.subject(step.target, policy);
              assertCheck(subject, step, labels, what);
              if (step.resolution === undefined) {
                // the default policy is ALLOW_OVERRIDES
                assertCheck(assignments.subject(step.target), step, labels, `${what} (default policy)`);
              }
              assertFails('UNSUPPORTED_OPERATION', `${what}: grant`, () => subject.grant('a.b'));
              assertFails('UNSUPPORTED_OPERATION', `${what}: revoke`, () => subject.revoke('a.b'));
              break;
            }
            case 'roleDenies':
              expectKeys(what, step, ['op', 'role', 'node', 'expect', 'error']);
              if ('error' in step) {
                assertFails(step.error, what, () => roleOf(step.role).denies(step.node));
              } else {
                assert.equal(roleOf(step.role).denies(step.node), step.expect, what);
              }
              break;
            case 'rolePermits':
              expectKeys(what, step, ['op', 'role', 'node', 'context', 'expect', 'error']);
              if ('error' in step) {
                assertFails(step.error, what, () => roleOf(step.role).permissions.hasPermission(step.node, context));
              } else {
                assert.equal(roleOf(step.role).permissions.hasPermission(step.node, context), step.expect, what);
              }
              break;
            default:
              assert.fail(`${what}: unknown op`);
          }
        });
      });
    }
  });
});
