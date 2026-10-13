// Role behavior specific to the TypeScript port: asynchronous stores,
// atomicity under interleaving, and runtime checks the Java type system
// makes unnecessary. Decisions and cardinality rules themselves are
// covered by spec/role-cases.json.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  type AsyncRoleAssignmentStore,
  AsyncRoleAssignments,
  ContextPolicy,
  IllegalArgumentError,
  IllegalStateError,
  MemoryPermissionSubject,
  MemoryRoleAssignmentStore,
  PermissionResolutionPolicy,
  Pernorama,
  Provenance,
  Role,
  RoleAssignment,
  RoleAssignmentDecision,
  RoleAssignmentPolicy,
  RoleAssignments,
  RoleAssignmentStatus,
  type RoleAssignmentStore,
  RoleGroup,
  UnsupportedOperationError,
} from '../src/index.js';

const pause = (ms = 0): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function same(a: readonly RoleAssignment[], b: readonly RoleAssignment[]): boolean {
  return a.length === b.length && a.every((assignment, i) => assignment.equals(b[i]));
}

/**
 * A store shaped like a database adapter: every call waits, so concurrent
 * operations interleave, and `replace` compares and writes in one step,
 * as a transaction or a version check would.
 */
class SlowStore implements AsyncRoleAssignmentStore<string> {
  readonly lists = new Map<string, readonly RoleAssignment[]>();
  conflicts = 0;
  writes = 0;

  async assignments(target: string): Promise<readonly RoleAssignment[]> {
    await pause(Math.random() * 3);
    return this.lists.get(target) ?? [];
  }

  async replace(
    target: string,
    expected: readonly RoleAssignment[],
    updated: readonly RoleAssignment[],
  ): Promise<boolean> {
    await pause(Math.random() * 3);
    // the atomic part: nothing is awaited between the comparison and the write
    if (!same(this.lists.get(target) ?? [], expected)) {
      this.conflicts++;
      return false;
    }
    this.lists.set(target, updated);
    this.writes++;
    return true;
  }
}

function rolesIn(group: RoleGroup, count: number): Role[] {
  return Array.from({ length: count }, (_, i) =>
    Role.builder(`role-${i}`).group(group).permission(`feature.${i}`).build(),
  );
}

describe('AsyncRoleAssignments', () => {
  it('assigns, replaces, rejects and unassigns like the synchronous API', async () => {
    const plan = RoleGroup.builder('plan').maxAssignments(1).assignmentPolicy(RoleAssignmentPolicy.REPLACE_EXISTING).build();
    const pro = Role.builder('pro').group(plan).permission('app.pro').build();
    const max = Role.builder('max').group(plan).permission('app.max').build();
    const assignments = Pernorama.create().newAsyncRoleAssignments(new SlowStore());

    assert.equal((await assignments.assign('alice', pro)).status, RoleAssignmentStatus.ASSIGNED);
    assert.equal((await assignments.assign('alice', pro)).status, RoleAssignmentStatus.NO_CHANGE);
    const replaced = await assignments.assign('alice', max);
    assert.equal(replaced.status, RoleAssignmentStatus.REPLACED);
    assert.equal(replaced.previousRole, pro);
    assert.equal(replaced.currentRole, max);
    assert.deepEqual((await assignments.roles('alice')).map(String), ['max']);
    assert.deepEqual((await assignments.assignments('alice')).map(String), ['max']);
    assert.equal((await assignments.unassign('alice', pro)).status, RoleAssignmentStatus.NO_CHANGE);
    assert.equal((await assignments.unassign('alice', max)).status, RoleAssignmentStatus.UNASSIGNED);
    assert.deepEqual(await assignments.roles('alice'), []);
    await assert.rejects(assignments.assign('alice', pro, ''), IllegalArgumentError);
    await assert.rejects(assignments.roles('alice', ''), IllegalArgumentError);
    await assert.rejects(assignments.assign(null as never, pro), IllegalArgumentError);
  });

  it('concurrent assignments never take an exclusive group over its maximum', async () => {
    const group = RoleGroup.builder('exclusive').maxAssignments(1).assignmentPolicy(RoleAssignmentPolicy.REPLACE_EXISTING).build();
    const roles = rolesIn(group, 25);
    const store = new SlowStore();
    const assignments = new AsyncRoleAssignments(store);

    const results = await Promise.all(roles.map((role) => assignments.assign('alice', role)));

    const held = await assignments.roles('alice');
    assert.equal(held.length, 1, 'exactly one role survives');
    assert.equal(results.filter((r) => r.status === RoleAssignmentStatus.ASSIGNED).length, 1);
    assert.equal(results.filter((r) => r.status === RoleAssignmentStatus.REPLACED).length, 24);
    for (const result of results) {
      if (result.status === RoleAssignmentStatus.REPLACED) {
        assert.equal(result.removedRoles.length, 1, 'each replacement swapped exactly one role out');
      }
    }
    // every role but the survivor was removed exactly once: no assignment was lost or applied twice
    const removed = results.flatMap((r) => r.removedRoles.map((role) => role.id)).sort();
    const expected = roles.map((role) => role.id).filter((id) => id !== held[0]!.id).sort();
    assert.deepEqual(removed, expected);
    assert.equal(store.writes, 25);
    assert.ok(store.conflicts > 0, 'the test did interleave');
  });

  it('concurrent assignments never take a REJECT group over its maximum', async () => {
    const group = RoleGroup.builder('team').maxAssignments(3).build();
    const roles = rolesIn(group, 20);
    const store = new SlowStore();
    const assignments = new AsyncRoleAssignments(store);

    const results = await Promise.all(roles.map((role) => assignments.assign('alice', role)));

    assert.equal(results.filter((r) => r.status === RoleAssignmentStatus.ASSIGNED).length, 3);
    assert.equal(results.filter((r) => r.status === RoleAssignmentStatus.REJECTED).length, 17);
    assert.equal((await assignments.roles('alice')).length, 3);
    assert.equal(store.writes, 3);
  });

  it('concurrent unassignments never take a group under its minimum', async () => {
    const group = RoleGroup.builder('tier').minAssignments(2).maxAssignments(10).build();
    const roles = rolesIn(group, 8);
    const assignments = new AsyncRoleAssignments(new SlowStore());
    for (const role of roles) {
      await assignments.assign('alice', role);
    }

    const results = await Promise.all(roles.map((role) => assignments.unassign('alice', role)));

    assert.equal(results.filter((r) => r.status === RoleAssignmentStatus.UNASSIGNED).length, 6);
    assert.equal(results.filter((r) => r.status === RoleAssignmentStatus.REJECTED).length, 2);
    assert.equal((await assignments.roles('alice')).length, 2);
  });

  it('a replacement is one write: no reader sees the target without a role', async () => {
    const group = RoleGroup.builder('exclusive').maxAssignments(1).assignmentPolicy(RoleAssignmentPolicy.REPLACE_EXISTING).build();
    const roles = rolesIn(group, 10);
    const store = new SlowStore();
    const assignments = new AsyncRoleAssignments(store);
    await assignments.assign('alice', roles[0]!);

    let reading = true;
    const observed: number[] = [];
    const reader = (async () => {
      while (reading) {
        observed.push((await assignments.roles('alice')).length);
      }
    })();
    for (const role of roles.slice(1)) {
      await assignments.assign('alice', role);
    }
    reading = false;
    await reader;

    assert.ok(observed.length > 0);
    assert.ok(observed.every((count) => count === 1), `observed role counts ${[...new Set(observed)].join(', ')}`);
  });

  it('consults the policy again when a concurrent change forces a retry', async () => {
    let consulted = 0;
    const counting: RoleAssignmentPolicy = {
      decide: (_group, held) => {
        consulted++;
        return RoleAssignmentDecision.replace(held);
      },
    };
    const group = RoleGroup.builder('exclusive').maxAssignments(1).assignmentPolicy(counting).build();
    const roles = rolesIn(group, 12);
    const assignments = new AsyncRoleAssignments(new SlowStore());

    await Promise.all(roles.map((role) => assignments.assign('alice', role)));

    assert.ok(consulted > 11, `the policy was consulted ${consulted} times for 11 replacements`);
    assert.equal((await assignments.roles('alice')).length, 1);
  });

  it('a policy that breaks the limits rejects the call and writes nothing', async () => {
    const broken: RoleAssignmentPolicy = { decide: () => RoleAssignmentDecision.replace([]) };
    const group = RoleGroup.builder('g').maxAssignments(1).assignmentPolicy(broken).build();
    const [first, second] = rolesIn(group, 2);
    const store = new SlowStore();
    const assignments = new AsyncRoleAssignments(store);
    await assignments.assign('alice', first!);

    await assert.rejects(assignments.assign('alice', second!), IllegalStateError);
    assert.equal(store.writes, 1);
    assert.deepEqual((await assignments.roles('alice')).map(String), ['role-0']);
  });

  it('subject() loads once and answers synchronously from that snapshot', async () => {
    const admin = Role.builder('admin').permission('students.*').build();
    const limited = Role.builder('limited').permission('-students.delete').build();
    const store = new SlowStore();
    const assignments = new AsyncRoleAssignments(store, ContextPolicy.GLOBAL_FALLBACK);
    await assignments.assign('alice', admin);
    await assignments.assign('alice', limited, 'academy:1');

    const alice = await assignments.subject('alice');
    assert.equal(alice.hasPermission('students.delete'), true);
    assert.equal(alice.hasPermission('students.delete', 'academy:1'), false);
    assert.equal(alice.hasPermission('students.read', 'academy:1'), true);
    assert.equal(alice.explain!('students.delete', 'academy:1').decidingLayer, 'EXACT_CONTEXT');
    assert.equal(alice.explain!('students.delete', 'academy:1').provenance, Provenance.COMPLETE);
    assert.throws(() => alice.grant('a.b'), UnsupportedOperationError);
    assert.equal(String(alice), 'AsyncRoleAssignments.subject(alice)');

    await assignments.unassign('alice', admin);
    assert.equal(alice.hasPermission('students.read'), true, 'a snapshot does not see later changes');
    assert.equal((await assignments.subject('alice')).hasPermission('students.read'), false);

    const strict = await assignments.subject('alice', PermissionResolutionPolicy.DENY_OVERRIDES);
    assert.equal(strict.hasPermission('students.delete', 'academy:1'), false);
    await assert.rejects(assignments.subject('alice', {} as never), IllegalArgumentError);
  });

  it('accepts a synchronous store too', async () => {
    const role = Role.builder('a').permission('x.y').build();
    const assignments = new AsyncRoleAssignments(new MemoryRoleAssignmentStore<string>());
    assert.equal((await assignments.assign('alice', role)).status, RoleAssignmentStatus.ASSIGNED);
    assert.equal((await assignments.subject('alice')).hasPermission('x.y'), true);
  });

  it('rejects a store that answers with something else', async () => {
    const role = Role.builder('a').build();
    const noList = { assignments: async () => null, replace: async () => true } as never;
    await assert.rejects(new AsyncRoleAssignments<string>(noList).assign('alice', role), IllegalStateError);
    const notAssignments = { assignments: async () => [{ role, context: null }], replace: async () => true } as never;
    await assert.rejects(new AsyncRoleAssignments<string>(notAssignments).roles('alice'), IllegalStateError);
    const noAnswer = { assignments: async () => [], replace: async () => undefined } as never;
    await assert.rejects(new AsyncRoleAssignments<string>(noAnswer).assign('alice', role), IllegalStateError);
    assert.throws(() => new AsyncRoleAssignments<string>({} as never), IllegalArgumentError);
  });
});

describe('RoleAssignments (synchronous)', () => {
  it('refuses an asynchronous store instead of treating its promises as answers', () => {
    const role = Role.builder('a').build();
    const assignments = new RoleAssignments<string>(new SlowStore() as unknown as RoleAssignmentStore<string>);
    assert.throws(() => assignments.assign('alice', role), /AsyncRoleAssignments/);
    assert.throws(() => assignments.roles('alice'), IllegalStateError);
    assert.throws(() => assignments.subject('alice').hasPermission('a.b'), IllegalStateError);

    // a promise from replace() is truthy: it must not count as "written"
    const promising = {
      assignments: () => [],
      replace: () => Promise.resolve(false),
    } as unknown as RoleAssignmentStore<string>;
    assert.throws(() => new RoleAssignments<string>(promising).assign('alice', role), IllegalStateError);
  });

  it('retries from fresh state when the store reports a concurrent change', () => {
    const group = RoleGroup.builder('g').maxAssignments(1).assignmentPolicy(RoleAssignmentPolicy.REPLACE_EXISTING).build();
    const [first, second, intruder] = rolesIn(group, 3);
    const backing = new MemoryRoleAssignmentStore<string>();
    let interfere = true;
    const racing: RoleAssignmentStore<string> = {
      assignments: (target) => backing.assignments(target),
      replace: (target, expected, updated) => {
        if (interfere) {
          // someone else swaps the role between this call's read and its write
          interfere = false;
          backing.replace(target, backing.assignments(target), [new RoleAssignment(intruder!)]);
        }
        return backing.replace(target, expected, updated);
      },
    };
    const assignments = new RoleAssignments(racing);
    backing.replace('alice', [], [new RoleAssignment(first!)]);

    const result = assignments.assign('alice', second!);

    assert.equal(result.status, RoleAssignmentStatus.REPLACED);
    assert.deepEqual(result.removedRoles.map(String), ['role-2'], 'decided again from the fresh state');
    assert.deepEqual(assignments.roles('alice').map(String), ['role-1']);
  });

  it('subject() is a live view', () => {
    const role = Role.builder('a').permission('x.y').build();
    const assignments = new RoleAssignments<string>();
    const alice = assignments.subject('alice');
    assert.equal(alice.hasPermission('x.y'), false);
    assignments.assign('alice', role);
    assert.equal(alice.hasPermission('x.y'), true);
    assignments.unassign('alice', role);
    assert.equal(alice.hasPermission('x.y'), false);
    assert.equal(String(alice), 'RoleAssignments.subject(alice)');
  });

  it('a role backed by a subject follows that subject', () => {
    const backing = new MemoryPermissionSubject(['reports.read']);
    const role = Role.builder('db').permissions(backing).build();
    const assignments = new RoleAssignments<string>();
    assignments.assign('alice', role);
    const alice = assignments.subject('alice');
    assert.equal(alice.hasPermission('reports.write'), false);
    backing.grant('reports.write');
    assert.equal(alice.hasPermission('reports.write'), true);
    assert.equal(role.permissions, backing);
  });

  it('a custom resolution policy has to answer with a boolean', () => {
    const role = Role.builder('a').permission('x.y').build();
    const assignments = new RoleAssignments<string>();
    assignments.assign('alice', role);
    const asyncPolicy = { hasPermission: () => Promise.resolve(false) } as unknown as PermissionResolutionPolicy;
    const alice = assignments.subject('alice', asyncPolicy);
    assert.throws(() => alice.hasPermission('x.y'), IllegalStateError);
    assert.throws(() => alice.explain!('x.y'), IllegalStateError);
  });

  it('a custom assignment policy has to return a decision', () => {
    const nothing = { decide: () => undefined } as unknown as RoleAssignmentPolicy;
    const group = RoleGroup.builder('g').maxAssignments(1).assignmentPolicy(nothing).build();
    const [first, second] = rolesIn(group, 2);
    const assignments = new RoleAssignments<string>();
    assignments.assign('alice', first!);
    assert.throws(() => assignments.assign('alice', second!), IllegalStateError);
    assert.deepEqual(assignments.roles('alice').map(String), ['role-0']);
  });

  it('validates what it is given', () => {
    const role = Role.builder('a').build();
    const assignments = new RoleAssignments<string>();
    assert.throws(() => assignments.assign('alice', { id: 'a' } as never), IllegalArgumentError);
    assert.throws(() => assignments.assign(undefined as never, role), IllegalArgumentError);
    assert.throws(() => assignments.subject(null as never), IllegalArgumentError);
    assert.throws(() => new RoleAssignments<string>(new MemoryRoleAssignmentStore(), 'EXACT' as never), IllegalArgumentError);
    assert.throws(() => RoleGroup.builder('g').maxAssignments(1.5).build(), IllegalArgumentError);
    assert.throws(() => RoleGroup.builder('g').minAssignments(Number.NaN).build(), IllegalArgumentError);
    assert.throws(() => RoleGroup.builder('g').maxAssignments(2 ** 31).build(), IllegalArgumentError);
    assert.throws(() => RoleGroup.builder('g').assignmentPolicy(null as never), IllegalArgumentError);
    assert.throws(() => Role.builder('r').group({ id: 'g' } as never), IllegalArgumentError);
    assert.throws(() => Role.builder('r').permissions({} as never), IllegalArgumentError);
    assert.throws(
      () => Role.builder('r').permission('a.b').permissions(new MemoryPermissionSubject()).build(),
      IllegalStateError,
    );
    assert.equal(RoleGroup.builder('g').build().maxAssignments, RoleGroup.UNBOUNDED);
  });
});

describe('MemoryRoleAssignmentStore', () => {
  it('replaces only when the assignments are still the expected ones', () => {
    const a = new RoleAssignment(Role.builder('a').build());
    const b = new RoleAssignment(Role.builder('b').build(), 'ctx');
    const store = new MemoryRoleAssignmentStore<string>();

    assert.deepEqual(store.assignments('alice'), []);
    assert.equal(store.replace('alice', [a], [b]), false, 'stale expectation');
    assert.deepEqual(store.assignments('alice'), []);
    assert.equal(store.replace('alice', [], [a]), true);
    assert.equal(store.replace('alice', [], [b]), false);
    // equality is by role id and context, not by instance
    assert.equal(store.replace('alice', [new RoleAssignment(Role.builder('a').build())], [a, b]), true);
    assert.equal(store.replace('alice', [b, a], []), false, 'order matters');
    assert.deepEqual(store.assignments('alice').map(String), ['a', 'b @ ctx']);
    assert.ok(Object.isFrozen(store.assignments('alice')));
    assert.equal(store.replace('alice', [a, b], []), true);
    assert.deepEqual(store.assignments('alice'), []);
    assert.throws(() => store.assignments(null as never), IllegalArgumentError);
  });

  it('keeps its own copy of what it was given', () => {
    const a = new RoleAssignment(Role.builder('a').build());
    const store = new MemoryRoleAssignmentStore<string>();
    const updated = [a];
    store.replace('alice', [], updated);
    updated.push(new RoleAssignment(Role.builder('b').build()));
    assert.equal(store.assignments('alice').length, 1);
  });
});

describe('roles, groups and assignments as values', () => {
  it('compare by id, and an assignment by role id and context', () => {
    const group = RoleGroup.builder('g').build();
    const a = Role.builder('a').group(group).permission('x.y').build();
    assert.ok(a.equals(Role.builder('a').build()));
    assert.ok(!a.equals(Role.builder('b').build()));
    assert.ok(group.equals(RoleGroup.builder('g').maxAssignments(3).build()));
    assert.ok(new RoleAssignment(a, 'c').equals(new RoleAssignment(Role.builder('a').build(), 'c')));
    assert.ok(!new RoleAssignment(a, 'c').equals(new RoleAssignment(a)));
    assert.equal(new RoleAssignment(a).hasContext, false);
    assert.equal(String(new RoleAssignment(a, 'c')), 'a @ c');
    assert.equal(a.group, group);
    assert.equal(Role.builder('b').build().group, null);
    assert.ok(Object.isFrozen(a));
    assert.throws(() => a.permissions.grant('x.z'), UnsupportedOperationError);
    assert.throws(() => a.permissions.revoke('x.y'), UnsupportedOperationError);
  });

  it('a result describes what happened', () => {
    const group = RoleGroup.builder('g').maxAssignments(1).build();
    const [first, second] = rolesIn(group, 2);
    const assignments = new RoleAssignments<string>();
    assignments.assign('alice', first!, 'ctx');
    const rejected = assignments.assign('alice', second!, 'ctx');
    assert.equal(rejected.status, RoleAssignmentStatus.REJECTED);
    assert.equal(rejected.group, group);
    assert.equal(rejected.context, 'ctx');
    assert.equal(rejected.currentRole, null);
    assert.equal(rejected.previousRole, null);
    assert.equal(
      String(rejected),
      "RoleAssignmentResult[status=REJECTED, role=role-1, context=ctx, removed=[], reason=role group 'g' allows at most 1 role(s) and the target already holds 1]",
    );
    assert.ok(Object.isFrozen(rejected));
  });
});
