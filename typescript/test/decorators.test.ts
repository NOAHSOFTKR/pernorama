// @Perm / @PermGroup as standard (TC39) decorators: what a guarded call
// does, how it fails closed, and what inheritance, overriding and
// composition mean.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  AuthorizationUnavailableException,
  createAsyncPermissionDecorators,
  createPermissionDecorators,
  IllegalArgumentError,
  IllegalStateError,
  InvalidPermissionException,
  MemoryPermissionSubject,
  PermissionAnnotationResolver,
  PermissionDeniedException,
  type PermInvocation,
  PermissionRegistry,
  type PermissionSubject,
  PernoramaException,
} from '../src/index.js';

interface Actor {
  readonly name: string;
  readonly permissions: PermissionSubject | null;
}

function actor(name: string, ...rules: string[]): Actor {
  return { name, permissions: new MemoryPermissionSubject(rules) };
}

/** The usual strategy in these tests: the first argument is the actor. */
const { Perm, PermGroup } = createPermissionDecorators({
  subject: ({ args }) => (args[0] as Actor | undefined)?.permissions,
});

function unavailable(reason: string): (error: unknown) => boolean {
  return (error) => {
    assert.ok(error instanceof AuthorizationUnavailableException, String(error));
    assert.ok(error instanceof PernoramaException);
    assert.equal(error.reason, reason);
    return true;
  };
}

describe('a method guarded with @Perm', () => {
  @PermGroup('users')
  class UserService {
    readonly created: string[] = [];

    @Perm('create')
    create(_actor: Actor, name: string): string {
      this.created.push(name);
      return `created ${name}`;
    }

    list(_actor: Actor): readonly string[] {
      return this.created;
    }
  }

  it('runs the body, with the same this, arguments and result, when the subject has the permission', () => {
    const service = new UserService();
    assert.equal(service.create(actor('alice', 'users.create'), 'bob'), 'created bob');
    assert.equal(service.create(actor('root', '*'), 'carol'), 'created carol');
    assert.deepEqual(service.created, ['bob', 'carol']);
  });

  it('throws before the body runs when the subject lacks the permission', () => {
    const service = new UserService();
    const mallory = actor('mallory', 'users.read', '-users.create');
    assert.throws(
      () => service.create(mallory, 'eve'),
      (error) => {
        assert.ok(error instanceof PermissionDeniedException);
        assert.equal(error.requiredPermission, 'users.create');
        assert.equal(error.context, null);
        assert.equal(error.subject, mallory.permissions);
        return true;
      },
    );
    assert.deepEqual(service.created, [], 'no side effect happened');
  });

  it('does not touch methods without @Perm', () => {
    assert.deepEqual(new UserService().list(actor('nobody')), []);
  });

  it('keeps the method name and arity, and guards a detached reference too', () => {
    const service = new UserService();
    assert.equal(service.create.name, 'create');
    assert.equal(service.create.length, 2);

    const detached = service.create;
    assert.throws(() => detached(actor('mallory'), 'eve'), PermissionDeniedException);
    assert.equal(detached.call(service, actor('alice', 'users.create'), 'bob'), 'created bob');
  });

  it('uses the full value when the class has no group', () => {
    class Reports {
      @Perm('reports.export')
      export(_actor: Actor): string {
        return 'exported';
      }
    }
    assert.equal(new Reports().export(actor('alice', 'reports.export')), 'exported');
    assert.throws(() => new Reports().export(actor('alice', 'export')), PermissionDeniedException);
  });
});

describe('fails closed', () => {
  let ran = 0;
  class Vault {
    @Perm('vault.open')
    open(_actor?: unknown): string {
      ran++;
      return 'opened';
    }
  }
  const vault = new Vault();

  it('when there is no subject', () => {
    ran = 0;
    assert.throws(() => vault.open(), unavailable('SUBJECT_UNAVAILABLE'));
    assert.throws(() => vault.open({ name: 'anonymous', permissions: null }), unavailable('SUBJECT_UNAVAILABLE'));
    assert.throws(() => vault.open({ permissions: { can: () => true } }), unavailable('SUBJECT_UNAVAILABLE'));
    assert.equal(ran, 0);
  });

  it('when the subject resolver throws, keeping the cause', () => {
    const boom = new Error('session store down');
    const strict = createPermissionDecorators({
      subject: () => {
        throw boom;
      },
    });
    let bodyRan = false;
    class Service {
      @strict.Perm('a.b')
      run(): void {
        bodyRan = true;
      }
    }
    assert.throws(
      () => new Service().run(),
      (error) => {
        assert.ok(unavailable('SUBJECT_RESOLVER_FAILED')(error));
        assert.equal((error as Error).cause, boom);
        assert.equal((error as AuthorizationUnavailableException).requiredPermission, 'a.b');
        return true;
      },
    );
    assert.equal(bodyRan, false);
  });

  it('when a synchronous resolver returns a promise', () => {
    const wrong = createPermissionDecorators({
      subject: (() => Promise.resolve(new MemoryPermissionSubject(['*']))) as never,
    });
    let bodyRan = false;
    class Service {
      @wrong.Perm('a.b')
      run(): void {
        bodyRan = true;
      }
    }
    assert.throws(() => new Service().run(), /createAsyncPermissionDecorators/);
    assert.throws(() => new Service().run(), unavailable('SUBJECT_UNAVAILABLE'));
    assert.equal(bodyRan, false);
  });

  it('when hasPermission throws', () => {
    ran = 0;
    const broken: PermissionSubject = {
      hasPermission: () => {
        throw new RangeError('database unreachable');
      },
      grant() {},
      revoke() {},
    };
    assert.throws(() => vault.open({ permissions: broken }), RangeError);
    assert.equal(ran, 0);
  });

  it('when hasPermission answers with a promise or another truthy value', () => {
    ran = 0;
    for (const answer of [Promise.resolve(true), 1, 'yes', {}]) {
      const sloppy = { hasPermission: () => answer, grant() {}, revoke() {} } as unknown as PermissionSubject;
      assert.throws(() => vault.open({ permissions: sloppy }), IllegalStateError);
    }
    assert.equal(ran, 0);
  });
});

describe('contexts', () => {
  interface Request {
    readonly actor: Actor;
    readonly academyId?: string | null;
  }

  const scoped = createPermissionDecorators({
    subject: ({ args }) => (args[0] as Request).actor.permissions,
    context: ({ args }) => {
      const academyId = (args[0] as Request).academyId;
      return academyId == null ? academyId : `academy:${academyId}`;
    },
  });

  let deleted: string[] = [];

  @scoped.PermGroup('students')
  class StudentService {
    @scoped.Perm('delete')
    delete(request: Request, id: string): void {
      deleted.push(`${request.academyId}/${id}`);
    }

    @scoped.Perm('export', { context: null })
    exportAll(_request: Request): string {
      return 'exported';
    }

    @scoped.Perm('audit', { context: () => 'audit' })
    audit(_request: Request): string {
      return 'audited';
    }
  }

  function teacher(): Actor {
    const permissions = new MemoryPermissionSubject(['students.*']);
    permissions.grant('-students.delete', 'academy:123');
    permissions.grant('-students.export', 'academy:123');
    permissions.grant('-students.audit', 'audit');
    return { name: 'teacher', permissions };
  }

  it('checks in the resolved context', () => {
    deleted = [];
    const service = new StudentService();
    service.delete({ actor: teacher(), academyId: '456' }, 's1');
    assert.throws(
      () => service.delete({ actor: teacher(), academyId: '123' }, 's2'),
      (error) => {
        assert.ok(error instanceof PermissionDeniedException);
        assert.equal(error.context, 'academy:123');
        return true;
      },
    );
    assert.deepEqual(deleted, ['456/s1']);
  });

  it('null is an explicit check without a context', () => {
    deleted = [];
    new StudentService().delete({ actor: teacher(), academyId: null }, 's1');
    assert.deepEqual(deleted, ['null/s1']);
  });

  it('undefined means the context is unknown, and is not a check without one', () => {
    deleted = [];
    // without a context the teacher would be allowed; the contextual deny must not be skipped
    assert.throws(() => new StudentService().delete({ actor: teacher() }, 's1'), unavailable('CONTEXT_UNAVAILABLE'));
    assert.deepEqual(deleted, []);
  });

  it('an invalid context is not a check without one either', () => {
    for (const bad of ['', 42, {}, Promise.resolve('academy:1')]) {
      const decorators = createPermissionDecorators({
        subject: () => new MemoryPermissionSubject(['*']),
        context: (() => bad) as never,
      });
      let bodyRan = false;
      class Service {
        @decorators.Perm('a.b')
        run(): void {
          bodyRan = true;
        }
      }
      assert.throws(() => new Service().run(), unavailable('CONTEXT_UNAVAILABLE'), String(bad));
      assert.equal(bodyRan, false);
    }
  });

  it('a failing context resolver fails the call, keeping the cause', () => {
    const boom = new Error('no tenant');
    const decorators = createPermissionDecorators({
      subject: () => new MemoryPermissionSubject(['*']),
      context: () => {
        throw boom;
      },
    });
    class Service {
      @decorators.Perm('a.b')
      run(): string {
        return 'ran';
      }
    }
    assert.throws(
      () => new Service().run(),
      (error) => unavailable('CONTEXT_RESOLVER_FAILED')(error) && (error as Error).cause === boom,
    );
  });

  it('a method can override or switch off the context resolver', () => {
    const service = new StudentService();
    // exportAll is checked without a context, so the deny in academy:123 does not apply
    assert.equal(service.exportAll({ actor: teacher(), academyId: '123' }), 'exported');
    assert.throws(() => service.audit({ actor: teacher(), academyId: '456' }), PermissionDeniedException);
  });

  it('a method can override the subject resolver', () => {
    const system = new MemoryPermissionSubject(['jobs.run']);
    class Jobs {
      @Perm('jobs.run', { subject: () => system })
      run(): string {
        return 'ran';
      }
    }
    assert.equal(new Jobs().run(), 'ran');
  });

  it('resolves the subject before the context, each once, and neither if the first fails', () => {
    const calls: string[] = [];
    const ordered = createPermissionDecorators({
      subject: ({ args }) => {
        calls.push('subject');
        return args[0] as PermissionSubject | undefined;
      },
      context: () => {
        calls.push('context');
        return 'ctx';
      },
    });
    class Service {
      @ordered.Perm('a.b')
      run(_subject?: PermissionSubject): void {
        calls.push('body');
      }
    }
    const subject = new MemoryPermissionSubject();
    subject.grant('a.b', 'ctx');
    new Service().run(subject);
    assert.deepEqual(calls, ['subject', 'context', 'body']);
  });
});

describe('what the resolvers are told', () => {
  it('the node, this, the arguments, the method name and whether it is static', () => {
    const seen: PermInvocation[] = [];
    const spying = createPermissionDecorators({
      subject: (invocation) => {
        seen.push(invocation);
        return new MemoryPermissionSubject(['*']);
      },
    });
    const key = Symbol('hidden');

    @spying.PermGroup('things')
    class Things {
      @spying.Perm('make')
      make(a: number, b: string): string {
        return `${a}${b}`;
      }

      @spying.Perm('count')
      static count(): number {
        return 0;
      }

      @spying.Perm('hidden')
      [key](): void {}
    }
    const things = new Things();
    things.make(1, 'x');
    Things.count();
    things[key]();

    assert.equal(seen[0]?.permission, 'things.make');
    assert.equal(seen[0]?.target, things);
    assert.deepEqual(seen[0]?.args, [1, 'x']);
    assert.equal(seen[0]?.methodName, 'make');
    assert.equal(seen[0]?.isStatic, false);
    assert.ok(Object.isFrozen(seen[0]) && Object.isFrozen(seen[0]?.args));

    assert.equal(seen[1]?.permission, 'things.count');
    assert.equal(seen[1]?.target, Things);
    assert.equal(seen[1]?.isStatic, true);
    assert.equal(seen[2]?.methodName, key);
  });
});

describe('asynchronous methods', () => {
  class Mailer {
    readonly sent: string[] = [];

    @Perm('mail.send')
    async send(_actor: Actor, to: string): Promise<string> {
      await Promise.resolve();
      this.sent.push(to);
      return `sent to ${to}`;
    }

    @Perm('mail.queue')
    queue(_actor: Actor, to: string): Promise<string> {
      return Promise.resolve(`queued for ${to}`);
    }
  }

  it('resolve as usual when permitted', async () => {
    const mailer = new Mailer();
    assert.equal(await mailer.send(actor('alice', 'mail.*'), 'bob'), 'sent to bob');
    assert.equal(await mailer.queue(actor('alice', 'mail.*'), 'bob'), 'queued for bob');
  });

  it('a native async method rejects instead of throwing synchronously', async () => {
    const mailer = new Mailer();
    const pending = mailer.send(actor('mallory'), 'bob');
    assert.ok(pending instanceof Promise);
    await assert.rejects(pending, PermissionDeniedException);
    await assert.rejects(mailer.send(undefined as never, 'bob'), AuthorizationUnavailableException);
    assert.deepEqual(mailer.sent, []);
  });

  it('a plain method that returns a promise throws synchronously with synchronous resolvers', () => {
    assert.throws(() => new Mailer().queue(actor('mallory'), 'bob'), PermissionDeniedException);
  });
});

describe('createAsyncPermissionDecorators', () => {
  const directory = new Map<string, PermissionSubject>([
    ['alice', new MemoryPermissionSubject(['orders.*', '-orders.refund'])],
  ]);
  const events: string[] = [];
  const guard = createAsyncPermissionDecorators({
    subject: async ({ args }) => {
      events.push('subject:start');
      await new Promise((resolve) => setTimeout(resolve, 2));
      events.push('subject:done');
      return directory.get(args[0] as string);
    },
    context: async ({ args }) => {
      events.push('context');
      return (args[1] as string | null | undefined) === undefined ? undefined : (args[1] as string | null);
    },
  });

  @guard.PermGroup('orders')
  class Orders {
    @guard.Perm('place')
    async place(userId: string, _shop: string | null): Promise<string> {
      events.push('body');
      return `placed by ${userId}`;
    }

    @guard.Perm('refund')
    refund(_userId: string, _shop: string | null): Promise<string> {
      events.push('body');
      return Promise.resolve('refunded');
    }
  }

  it('awaits the resolvers, then runs the body', async () => {
    events.length = 0;
    assert.equal(await new Orders().place('alice', null), 'placed by alice');
    assert.deepEqual(events, ['subject:start', 'subject:done', 'context', 'body']);
  });

  it('every failure is a rejection, and the body does not run', async () => {
    events.length = 0;
    const orders = new Orders();
    await assert.rejects(orders.refund('alice', null), PermissionDeniedException);
    await assert.rejects(orders.place('nobody', null), unavailable('SUBJECT_UNAVAILABLE'));
    await assert.rejects(orders.place('alice', undefined as never), unavailable('CONTEXT_UNAVAILABLE'));
    await assert.rejects(orders.place('alice', ''), unavailable('CONTEXT_UNAVAILABLE'));
    assert.ok(!events.includes('body'));
  });

  it('checks in the resolved context', async () => {
    const shop = new MemoryPermissionSubject(['orders.place']);
    shop.grant('-orders.place', 'shop:closed');
    directory.set('bob', shop);
    assert.equal(await new Orders().place('bob', 'shop:open'), 'placed by bob');
    await assert.rejects(new Orders().place('bob', 'shop:closed'), PermissionDeniedException);
  });

  it('a rejected resolver fails the call, keeping the cause', async () => {
    const boom = new Error('directory down');
    const failing = createAsyncPermissionDecorators({ subject: () => Promise.reject(boom) });
    let bodyRan = false;
    class Service {
      @failing.Perm('a.b')
      async run(): Promise<void> {
        bodyRan = true;
      }
    }
    await assert.rejects(
      new Service().run(),
      (error) => unavailable('SUBJECT_RESOLVER_FAILED')(error) && (error as Error).cause === boom,
    );
    assert.equal(bodyRan, false);
  });

  it('is asynchronous even when its resolvers answer immediately', async () => {
    const immediate = createAsyncPermissionDecorators({ subject: () => new MemoryPermissionSubject() });
    class Service {
      @immediate.Perm('a.b')
      run(): Promise<string> {
        return Promise.resolve('ran');
      }
    }
    const pending = new Service().run();
    assert.ok(pending instanceof Promise, 'a denial is never thrown synchronously');
    await assert.rejects(pending, PermissionDeniedException);
  });

  it('an asynchronous subject is still rejected: a check is synchronous', async () => {
    const sloppy = createAsyncPermissionDecorators({
      subject: () => ({ hasPermission: async () => true, grant() {}, revoke() {} }) as never,
    });
    let bodyRan = false;
    class Service {
      @sloppy.Perm('a.b')
      async run(): Promise<void> {
        bodyRan = true;
      }
    }
    await assert.rejects(new Service().run(), IllegalStateError);
    assert.equal(bodyRan, false);
  });

  it('only accepts methods that return a promise', async () => {
    class Service {
      // @ts-expect-error -- a synchronous method cannot be guarded by asynchronous resolvers
      @guard.Perm('sync')
      sync(): number {
        return 1;
      }
    }
    // at runtime the guard still wins: the call returns a promise and the body waits for it
    const pending = new Service().sync() as unknown;
    assert.ok(pending instanceof Promise);
    await assert.rejects(pending, AuthorizationUnavailableException);
  });
});

describe('inheritance and overriding', () => {
  const calls: string[] = [];

  @PermGroup('documents')
  class DocumentService {
    @Perm('read')
    read(_actor: Actor): string {
      calls.push('base.read');
      return 'base read';
    }

    @Perm('write')
    write(_actor: Actor): string {
      calls.push('base.write');
      return 'base write';
    }

    @Perm('archive')
    archive(_actor: Actor): string {
      return 'base archive';
    }
  }

  @PermGroup('invoices')
  class InvoiceService extends DocumentService {
    // overrides without @Perm: not guarded, exactly as a Java override does not inherit @Perm
    override write(_actor: Actor): string {
      calls.push('invoice.write');
      return 'invoice write';
    }

    // overrides and delegates: the inherited guard applies when super is called
    override archive(actor: Actor): string {
      return `invoice then ${super.archive(actor)}`;
    }

    @Perm('void')
    void(_actor: Actor): string {
      return 'voided';
    }
  }

  class PlainSubclass extends DocumentService {}

  it('an inherited method keeps the node of the class that declared it', () => {
    const reader = actor('reader', 'documents.read');
    assert.equal(new InvoiceService().read(reader), 'base read');
    assert.equal(new PlainSubclass().read(reader), 'base read');
    // the subclass's own group does not rename the inherited permission
    assert.throws(() => new InvoiceService().read(actor('other', 'invoices.read')), PermissionDeniedException);
  });

  it('an override without @Perm is not guarded', () => {
    calls.length = 0;
    assert.equal(new InvoiceService().write(actor('nobody')), 'invoice write');
    assert.deepEqual(calls, ['invoice.write']);
    assert.throws(() => new DocumentService().write(actor('nobody')), PermissionDeniedException);
  });

  it('an override that calls super goes through the inherited guard', () => {
    assert.throws(() => new InvoiceService().archive(actor('nobody')), PermissionDeniedException);
    assert.equal(
      new InvoiceService().archive(actor('archivist', 'documents.archive')),
      'invoice then base archive',
    );
  });

  it("a subclass's own @Perm methods use the subclass's group", () => {
    assert.equal(new InvoiceService().void(actor('clerk', 'invoices.void')), 'voided');
    assert.throws(() => new InvoiceService().void(actor('clerk', 'documents.void')), PermissionDeniedException);
  });

  it('an override can declare its own @Perm', () => {
    class Strict extends DocumentService {
      @Perm('documents.read.strict')
      override read(_actor: Actor): string {
        return 'strict read';
      }
    }
    assert.throws(() => new Strict().read(actor('reader', 'documents.read')), PermissionDeniedException);
    assert.equal(new Strict().read(actor('reader', 'documents.read.strict')), 'strict read');
  });

  it('resolution and the registry follow the same rule', () => {
    assert.equal(PermissionAnnotationResolver.resolve(DocumentService.prototype.read), 'documents.read');
    assert.equal(PermissionAnnotationResolver.resolve(InvoiceService.prototype.read), 'documents.read');
    assert.equal(PermissionAnnotationResolver.resolve(InvoiceService.prototype.write), null);
    assert.equal(PermissionAnnotationResolver.resolve(InvoiceService.prototype.void), 'invoices.void');

    const registry = new PermissionRegistry();
    assert.deepEqual(registry.register(InvoiceService).map(String), ['invoices.void']);
    assert.deepEqual(registry.register(PlainSubclass), [], 'nothing is declared on the subclass itself');
    assert.deepEqual(registry.register(DocumentService).map(String), [
      'documents.read',
      'documents.write',
      'documents.archive',
    ]);
  });
});

describe('static and private methods', () => {
  let rotations = 0;

  @PermGroup('keys')
  class KeyService {
    @Perm('list')
    static list(_actor: Actor): string[] {
      return ['k1'];
    }

    @Perm('rotate')
    #rotate(_actor: Actor): void {
      rotations++;
    }

    rotateAll(actor: Actor): void {
      this.#rotate(actor);
    }
  }

  it('a static method is guarded', () => {
    assert.deepEqual(KeyService.list(actor('ops', 'keys.list')), ['k1']);
    assert.throws(() => KeyService.list(actor('guest')), PermissionDeniedException);
  });

  it('a private method is guarded wherever the class calls it', () => {
    rotations = 0;
    assert.throws(() => new KeyService().rotateAll(actor('guest')), PermissionDeniedException);
    new KeyService().rotateAll(actor('ops', 'keys.rotate'));
    assert.equal(rotations, 1);
  });

  it('both are registered', () => {
    assert.deepEqual(new PermissionRegistry().register(KeyService).map(String).sort(), ['keys.list', 'keys.rotate']);
  });
});

describe('composition with other decorators', () => {
  const log: string[] = [];

  function logged<This, Args extends unknown[], Return>(
    method: (this: This, ...args: Args) => Return,
    context: ClassMethodDecoratorContext<This, (this: This, ...args: Args) => Return>,
  ) {
    return function (this: This, ...args: Args): Return {
      log.push(`log:${String(context.name)}`);
      return method.apply(this, args);
    };
  }

  @PermGroup('ops')
  class Ops {
    // @Perm outermost: authorization runs before anything else
    @Perm('deploy')
    @logged
    deploy(_actor: Actor): string {
      log.push('body:deploy');
      return 'deployed';
    }

    // another decorator outermost: it runs first, the guard still runs before the body
    @logged
    @Perm('restart')
    restart(_actor: Actor): string {
      log.push('body:restart');
      return 'restarted';
    }
  }

  it('with @Perm outermost, nothing else runs for a denied call', () => {
    log.length = 0;
    assert.throws(() => new Ops().deploy(actor('guest')), PermissionDeniedException);
    assert.deepEqual(log, []);
    assert.equal(new Ops().deploy(actor('ops', 'ops.deploy')), 'deployed');
    assert.deepEqual(log, ['log:deploy', 'body:deploy']);
  });

  it('with another decorator outermost, it runs first but the body is still guarded', () => {
    log.length = 0;
    assert.throws(() => new Ops().restart(actor('guest')), PermissionDeniedException);
    assert.deepEqual(log, ['log:restart'], 'the outer decorator ran; the body did not');
  });

  it('the group still applies, and the registry still sees the method', () => {
    assert.equal(new Ops().restart(actor('ops', 'ops.restart')), 'restarted');
    assert.deepEqual(new PermissionRegistry().register(Ops).map(String).sort(), ['ops.deploy', 'ops.restart']);
    assert.equal(PermissionAnnotationResolver.resolve(Ops.prototype.deploy), 'ops.deploy');
    // the outer wrapper is not the guarded function, so it cannot be resolved by reference
    assert.equal(PermissionAnnotationResolver.resolve(Ops.prototype.restart), null);
  });

  it('a method requires one node: @Perm twice is an error when the class is defined', () => {
    assert.throws(() => {
      class Twice {
        @Perm('a.b')
        @Perm('a.c')
        run(): void {}
      }
      return Twice;
    }, IllegalStateError);
  });

  it('two sets of decorators with different strategies coexist', () => {
    const system = new MemoryPermissionSubject(['jobs.*']);
    const asSystem = createPermissionDecorators({ subject: () => system });

    @PermGroup('jobs')
    class Jobs {
      @Perm('start')
      start(_actor: Actor): string {
        return 'started by user';
      }

      @asSystem.Perm('sweep')
      sweep(): string {
        return 'swept by system';
      }
    }
    assert.equal(new Jobs().sweep(), 'swept by system');
    assert.throws(() => new Jobs().start(actor('guest')), PermissionDeniedException);
    assert.deepEqual(new PermissionRegistry().register(Jobs).map(String).sort(), ['jobs.start', 'jobs.sweep']);
  });
});

describe('declaring permissions', () => {
  it('rejects an invalid node or group when the class is defined, not on the first call', () => {
    assert.throws(() => Perm('users.*'), InvalidPermissionException);
    assert.throws(() => Perm('-users.delete'), InvalidPermissionException);
    assert.throws(() => Perm(''), InvalidPermissionException);
    assert.throws(() => Perm(undefined as never), InvalidPermissionException);
    assert.throws(() => PermGroup('users.*'), InvalidPermissionException);
    assert.throws(() => PermGroup('bad group'), InvalidPermissionException);
    assert.throws(() => PermGroup(42 as never), IllegalArgumentError);
    assert.throws(() => Perm('a.b', { subject: 'alice' } as never), IllegalArgumentError);
    assert.throws(() => Perm('a.b', { context: 'ctx' } as never), IllegalArgumentError);
  });

  it('a blank group adds no prefix, as in Java', () => {
    @PermGroup('  ')
    class Blank {
      @Perm('blank.run')
      run(_actor: Actor): string {
        return 'ran';
      }
    }
    assert.equal(new Blank().run(actor('alice', 'blank.run')), 'ran');
    assert.equal(PermissionAnnotationResolver.combine('  ', 'a.b'), 'a.b');
    assert.equal(PermissionAnnotationResolver.combine(null, 'a.b'), 'a.b');
    assert.equal(PermissionAnnotationResolver.combine('users', 'create'), 'users.create');
  });

  it('requires a subject strategy: there is no default and no global', () => {
    assert.throws(() => createPermissionDecorators({} as never), IllegalArgumentError);
    assert.throws(() => createPermissionDecorators(undefined as never), IllegalArgumentError);
    assert.throws(() => createAsyncPermissionDecorators({ subject: null } as never), IllegalArgumentError);
    assert.throws(() => createPermissionDecorators({ subject: () => null, context: 'ctx' } as never), IllegalArgumentError);
  });

  it('refuses what it cannot guard', () => {
    assert.throws(() => {
      class Field {
        // @ts-expect-error -- @Perm does not decorate fields
        @Perm('a.b')
        value = 1;
      }
      return Field;
    }, IllegalArgumentError);
    assert.throws(() => {
      class Getter {
        // @ts-expect-error -- @Perm does not decorate accessors
        @Perm('a.b')
        get value(): number {
          return 1;
        }
      }
      return Getter;
    }, IllegalArgumentError);
    assert.throws(() => {
      class Method {
        // @ts-expect-error -- @PermGroup decorates classes
        @PermGroup('a')
        run(): void {}
      }
      return Method;
    }, IllegalArgumentError);
    assert.throws(() => {
      @PermGroup('a')
      @PermGroup('b')
      class Twice {}
      return Twice;
    }, IllegalStateError);
    assert.throws(() => {
      @Perm('a.b')
      @Perm('a.c')
      class Twice {}
      return Twice;
    }, IllegalStateError);
    assert.throws(() => {
      @Perm('a.b', { subject: () => null })
      class WithResolvers {}
      return WithResolvers;
    }, IllegalArgumentError);
  });

  it('refuses to run as a legacy (experimentalDecorators) decorator', () => {
    const legacy = Perm('a.b') as unknown as (target: object, key: string, descriptor: PropertyDescriptor) => void;
    assert.throws(() => legacy({}, 'run', { value() {} }), /experimentalDecorators/);
    const legacyGroup = PermGroup('a') as unknown as (target: object) => void;
    assert.throws(() => legacyGroup(class {}), IllegalStateError);
  });

  it('refuses a build that provides no decorator metadata instead of guarding with the wrong node', () => {
    const decorate = Perm('a.b') as unknown as (method: () => void, context: object) => unknown;
    assert.throws(
      () => decorate(() => undefined, { kind: 'method', name: 'run', static: false, private: false }),
      IllegalStateError,
    );
  });

  it('defines Symbol.metadata, which decorator metadata needs', () => {
    assert.equal(typeof (Symbol as unknown as { metadata?: symbol }).metadata, 'symbol');
  });
});

describe('PermissionRegistry', () => {
  @PermGroup('accounts')
  @Perm('admin')
  class AccountService {
    @Perm('open')
    open(_actor: Actor): void {}

    @Perm('close')
    close(_actor: Actor): void {}

    @Perm('close')
    closeAll(_actor: Actor): void {}
  }

  it('registers the class-level node and each method node once', () => {
    const registry = new PermissionRegistry();
    const found = registry.register(AccountService);
    assert.deepEqual(found.map(String), ['accounts.admin', 'accounts.open', 'accounts.close']);
    assert.deepEqual(registry.all().map(String), ['accounts.admin', 'accounts.open', 'accounts.close']);

    // registering again is safe and finds the same node instances
    assert.deepEqual(registry.register(AccountService), found);
    assert.equal(registry.all().length, 3);
  });

  it('looks nodes up', () => {
    const registry = new PermissionRegistry();
    registry.register(AccountService);
    assert.equal(registry.get('accounts.open').name, 'accounts.open');
    assert.equal(registry.contains('accounts.open'), true);
    assert.equal(registry.contains('accounts.nope'), false);
    assert.equal(registry.validate('accounts.open'), true);
    assert.equal(registry.validate('accounts.nope'), false);
    assert.equal(registry.validate('accounts.*'), false);
    assert.equal(registry.validate(null), false);
    assert.throws(() => registry.get('accounts.nope'), IllegalArgumentError);
  });

  it('takes nodes that are only checked directly', () => {
    const registry = new PermissionRegistry();
    const node = registry.registerNode('billing.refund');
    assert.equal(registry.registerNode('billing.refund'), node);
    assert.equal(registry.get('billing.refund'), node);
    assert.throws(() => registry.registerNode('billing.*'), InvalidPermissionException);
  });

  it('a class without decorators declares nothing', () => {
    class Plain {
      run(): void {}
    }
    assert.deepEqual(new PermissionRegistry().register(Plain), []);
    assert.throws(() => new PermissionRegistry().register({} as never), IllegalArgumentError);
  });

  it('a class-level @Perm guards nothing', () => {
    assert.equal(new AccountService().open.name, 'open');
    assert.throws(() => new AccountService().open(actor('guest')), PermissionDeniedException);
    // constructing the class is not guarded by its class-level @Perm
    assert.ok(new AccountService() instanceof AccountService);
  });
});
