// The examples in typescript/README.md, compiled and asserted, so that
// what the README promises is pinned by a test — as ReadmeExamplesTest
// does for the Java README. Keep the two in step when either changes.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  type AsyncRoleAssignmentStore,
  AuthorizationUnavailableException,
  CompositePermissionSubject,
  ContextPolicy,
  createAsyncPermissionDecorators,
  createPermissionDecorators,
  IllegalStateError,
  InvalidPermissionException,
  MemoryPermissionSubject,
  Permission,
  PermissionAnnotationResolver,
  PermissionDeniedException,
  type PermissionExplanation,
  PermissionGrant,
  PermissionNode,
  PermissionRegistry,
  PermissionResolver,
  type PermissionSubject,
  Pernorama,
  Role,
  type RoleAssignment,
  RoleAssignmentPolicy,
  RoleGroup,
  UnsupportedOperationError,
} from '../src/index.js';

describe('README', () => {
  it('introduction', () => {
    const user = new MemoryPermissionSubject(['users.*', '-users.delete']);

    assert.equal(Permission.check(user, 'users.create'), true);
    assert.equal(Permission.check(user, 'users.delete'), false);
  });

  it('Permissions', () => {
    assert.equal(PermissionNode.isValid('users.create'), true);
    assert.equal(PermissionNode.isValid('users.*'), false);
    assert.equal(PermissionResolver.isValidPattern('users.*'), true);
    assert.equal(PermissionResolver.isValidPattern('users.*.read'), false);

    const node = PermissionNode.of('users.profile.edit');
    assert.equal(node.parent()?.name, 'users.profile');
    assert.equal(node.isChildOf('users'), true);
  });

  it('Deny rules', () => {
    const user = new MemoryPermissionSubject(['users.*', '-users.delete']);

    assert.equal(user.hasPermission('users.create'), true);
    assert.equal(user.hasPermission('users.delete'), false);
    assert.equal(user.hasPermission('users.delete.hard'), true);

    user.grant('-users.delete.*');
    assert.equal(user.hasPermission('users.delete.hard'), false);

    // revoke does not carve a node out of a wildcard
    user.revoke('users.create');
    assert.equal(user.hasPermission('users.create'), true);
  });

  it('Contexts', () => {
    const pernorama = Pernorama.builder().contextPolicy(ContextPolicy.GLOBAL_FALLBACK).build();

    const teacher = pernorama.newSubject();
    teacher.grant('students.read');
    teacher.grant('students.edit', 'academy:123');
    teacher.grant('-students.read', 'academy:999');

    assert.equal(teacher.hasPermission('students.edit', 'academy:123'), true);
    assert.equal(teacher.hasPermission('students.edit'), false);
    assert.equal(teacher.hasPermission('students.read', 'academy:123'), true);
    assert.equal(teacher.hasPermission('students.read', 'academy:999'), false);

    // EXACT: a check in a context sees only the grants made in exactly that context
    const exact = Pernorama.create({ contextPolicy: ContextPolicy.EXACT }).newSubject(['students.read']);
    assert.equal(exact.hasPermission('students.read', 'academy:123'), false);
    assert.equal(exact.hasPermission('students.read'), true);
  });

  it('Checking without decorators', () => {
    const user = new MemoryPermissionSubject(['reports.export']);

    assert.equal(Permission.check(user, 'reports.export'), true);

    let caught: unknown;
    try {
      Permission.require(user, 'students.delete', 'academy:123');
    } catch (error) {
      caught = error;
    }
    assert.ok(caught instanceof PermissionDeniedException);
    assert.equal(caught.requiredPermission, 'students.delete');
    assert.equal(caught.context, 'academy:123');
  });

  it('Custom subjects', async () => {
    interface GrantTable {
      grantsOf(userId: string): Promise<{ rule: string; context: string | null }[]>;
    }

    class StoredSubject implements PermissionSubject {
      private constructor(
        private readonly grants: readonly PermissionGrant[],
        private readonly policy: ContextPolicy,
      ) {}

      static async load(db: GrantTable, userId: string, policy: ContextPolicy): Promise<StoredSubject> {
        const rows = await db.grantsOf(userId);
        return new StoredSubject(rows.map((row) => new PermissionGrant(row.rule, row.context)), policy);
      }

      hasPermission(node: string, context?: string | null): boolean {
        return this.policy.permits(this.grants, node, context);
      }

      explain(node: string, context?: string | null): PermissionExplanation {
        return this.policy.explain(this.grants, node, context);
      }

      grant(): never {
        throw new UnsupportedOperationError('grants are changed in the database');
      }

      revoke(): never {
        throw new UnsupportedOperationError('grants are changed in the database');
      }
    }

    const db: GrantTable = {
      grantsOf: async () => [
        { rule: 'students.*', context: null },
        { rule: '-students.delete', context: 'academy:123' },
      ],
    };
    const pernorama = Pernorama.create();
    const subject = await StoredSubject.load(db, 'alice', pernorama.contextPolicy);

    assert.equal(Permission.check(subject, 'students.delete'), true);
    assert.equal(Permission.check(subject, 'students.delete', 'academy:123'), false);
    assert.equal(Permission.explain(subject, 'students.delete', 'academy:123').decision, 'DENIED');

    // a hasPermission declared async is never read as "allowed"
    const sloppy = { hasPermission: async () => true, grant() {}, revoke() {} } as unknown as PermissionSubject;
    assert.throws(() => Permission.check(sloppy, 'students.delete'), IllegalStateError);
  });

  it('Roles', () => {
    const plan = RoleGroup.builder('plan')
      .maxAssignments(1)
      .assignmentPolicy(RoleAssignmentPolicy.REPLACE_EXISTING)
      .build();

    const pro = Role.builder('plan_pro').group(plan).permission('app.use').permission('app.plan.pro').build();
    const max5 = Role.builder('plan_max5').group(plan).permission('app.use').permission('app.plan.max5').build();

    const assignments = Pernorama.create().newRoleAssignments<string>();

    assert.equal(assignments.assign('alice', pro).status, 'ASSIGNED');
    const result = assignments.assign('alice', max5);
    assert.equal(result.status, 'REPLACED');
    assert.equal(result.previousRole?.id, 'plan_pro');

    const alice = assignments.subject('alice');
    assert.equal(alice.hasPermission('app.plan.max5'), true);
    assert.equal(alice.hasPermission('app.plan.pro'), false);

    // roles plus direct grants
    const ownGrants = new MemoryPermissionSubject(['profile.edit', '-app.use']);
    const user = new CompositePermissionSubject(ownGrants, assignments.subject('alice'));
    assert.equal(user.hasPermission('profile.edit'), true);
    assert.equal(user.hasPermission('app.use'), true, 'a deny in one source does not veto another');
  });

  it('Role assignments in a database', async () => {
    const teacher = Role.builder('teacher').permission('students.read').build();
    const pernorama = Pernorama.create();
    // a store is two methods: read, and compare-and-set
    const lists = new Map<string, readonly RoleAssignment[]>();
    const store: AsyncRoleAssignmentStore<string> = {
      async assignments(userId) {
        return lists.get(userId) ?? [];
      },
      async replace(userId, expected, updated) {
        const current = lists.get(userId) ?? [];
        if (current.length !== expected.length || !current.every((a, i) => a.equals(expected[i]))) {
          return false;
        }
        lists.set(userId, updated);
        return true;
      },
    };
    const assignments = pernorama.newAsyncRoleAssignments(store);

    await assignments.assign('user-1', teacher, 'academy:123');

    const subject = await assignments.subject('user-1');
    assert.equal(subject.hasPermission('students.read', 'academy:123'), true);
    assert.equal(subject.hasPermission('students.read', 'academy:456'), false);
  });

  it('Explaining a decision', () => {
    const pernorama = Pernorama.create();
    const user = pernorama.newSubject(['students.delete']);
    user.grant('-students.*', 'academy:123');

    const why = user.explain('students.delete', 'academy:123');

    assert.equal(why.allowed, false);
    assert.equal(why.decision, 'DENIED');
    assert.equal(why.decidingLayer, 'EXACT_CONTEXT');
    assert.equal(why.provenance, 'COMPLETE');
    assert.deepEqual(why.matches.map(String), ['-students.* @ academy:123 (decisive)', 'students.delete']);

    assert.equal(user.explain('orders.read').decision, 'NOT_COVERED');
  });

  describe('Decorators', () => {
    interface Actor {
      readonly permissions: PermissionSubject | null;
    }
    interface User {
      readonly name: string;
    }

    const { Perm, PermGroup } = createPermissionDecorators({
      subject: ({ args }) => (args[0] as Actor | undefined)?.permissions,
    });

    @PermGroup('users')
    class UserService {
      @Perm('create')
      create(_actor: Actor, name: string): User {
        return { name };
      }
    }

    it('a guarded call', () => {
      const service = new UserService();
      const admin: Actor = { permissions: new MemoryPermissionSubject(['users.create']) };
      const guest: Actor = { permissions: new MemoryPermissionSubject() };

      assert.deepEqual(service.create(admin, 'bob'), { name: 'bob' });
      assert.throws(() => service.create(guest, 'eve'), PermissionDeniedException);
      assert.throws(() => service.create({ permissions: null }, 'eve'), AuthorizationUnavailableException);
    });

    it('contexts', () => {
      interface Request {
        readonly actor: Actor;
        readonly academyId?: string;
      }

      const scoped = createPermissionDecorators({
        subject: ({ args }) => (args[0] as Request).actor.permissions,
        context: ({ args }) => {
          const academyId = (args[0] as Request).academyId;
          return academyId === undefined ? undefined : `academy:${academyId}`;
        },
      });
      const systemSubject = new MemoryPermissionSubject(['students.sweep']);

      @scoped.PermGroup('students')
      class StudentService {
        @scoped.Perm('delete')
        delete(_request: Request): string {
          return 'deleted';
        }

        @scoped.Perm('export', { context: null })
        export(_request: Request): string {
          return 'exported';
        }

        @scoped.Perm('sweep', { subject: () => systemSubject, context: null })
        sweep(): string {
          return 'swept';
        }
      }

      const permissions = new MemoryPermissionSubject(['students.*']);
      permissions.grant('-students.delete', 'academy:123');
      permissions.grant('-students.export', 'academy:123');
      const actor: Actor = { permissions };
      const service = new StudentService();

      assert.equal(service.delete({ actor, academyId: '456' }), 'deleted');
      assert.throws(() => service.delete({ actor, academyId: '123' }), PermissionDeniedException);
      // an unknown context is not a check without one
      assert.throws(() => service.delete({ actor }), AuthorizationUnavailableException);
      assert.equal(service.export({ actor, academyId: '123' }), 'exported');
      assert.equal(service.sweep(), 'swept');
    });

    it('asynchronous resolvers', async () => {
      interface Request {
        readonly userId: string;
      }
      const stored = new Map([['alice', new MemoryPermissionSubject(['orders.place'])]]);

      const guard = createAsyncPermissionDecorators({
        subject: async ({ args }) => stored.get((args[0] as Request).userId),
      });

      class Orders {
        @guard.Perm('orders.place')
        async place(_request: Request): Promise<string> {
          return 'placed';
        }
      }

      assert.equal(await new Orders().place({ userId: 'alice' }), 'placed');
      await assert.rejects(new Orders().place({ userId: 'nobody' }), AuthorizationUnavailableException);
    });

    it('inheritance and overriding', () => {
      class AuditedUserService extends UserService {
        // an override does not inherit @Perm
        override create(_actor: Actor, name: string): User {
          return { name: `audited ${name}` };
        }
      }
      class DelegatingUserService extends UserService {
        override create(actor: Actor, name: string): User {
          return super.create(actor, name);
        }
      }
      const guest: Actor = { permissions: new MemoryPermissionSubject() };

      assert.deepEqual(new AuditedUserService().create(guest, 'eve'), { name: 'audited eve' });
      assert.throws(() => new DelegatingUserService().create(guest, 'eve'), PermissionDeniedException);
      assert.throws(() => Perm('users.*'), InvalidPermissionException);
    });

    it('inspecting what was declared', () => {
      assert.equal(PermissionAnnotationResolver.resolve(UserService.prototype.create), 'users.create');

      const registry = new PermissionRegistry();
      registry.register(UserService);
      registry.registerNode('billing.refund');
      assert.deepEqual(registry.all().map(String), ['users.create', 'billing.refund']);
      assert.equal(registry.validate('users.create'), true);
    });
  });
});
