// Behavior that is specific to the TypeScript port: what the type system
// cannot guarantee at runtime, and the places where it deliberately fails
// closed. Decisions themselves are covered by the shared fixtures in
// test/conformance.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  CompositePermissionSubject,
  ContextPolicy,
  Contribution,
  Decision,
  IllegalArgumentError,
  IllegalStateError,
  InvalidPermissionException,
  Layer,
  MemoryPermissionSubject,
  Permission,
  PermissionDeniedException,
  PermissionExplanation,
  PermissionGrant,
  PermissionNode,
  PermissionResolver,
  type PermissionSubject,
  Pernorama,
  PernoramaException,
  Provenance,
  RuleMatch,
  UnsupportedOperationError,
} from '../src/index.js';

/** A subject written as if checks could be asynchronous: the classic way to authorize everything by accident. */
function asyncSubject(answer: boolean): PermissionSubject {
  return {
    hasPermission: (() => Promise.resolve(answer)) as unknown as PermissionSubject['hasPermission'],
    grant: () => undefined,
    revoke: () => undefined,
  };
}

describe('a subject that does not answer with a boolean is never read as "allowed"', () => {
  for (const answer of [true, false]) {
    it(`Permission.check/require/explain reject a Promise<${answer}>`, () => {
      const subject = asyncSubject(answer);
      assert.throws(() => Permission.check(subject, 'users.read'), IllegalStateError);
      assert.throws(() => Permission.require(subject, 'users.read'), IllegalStateError);
      assert.throws(() => Permission.explain(subject, 'users.read'), IllegalStateError);
    });
  }

  it('a composite rejects such a source instead of treating the promise as true', () => {
    const composite = new CompositePermissionSubject(asyncSubject(false));
    assert.throws(() => composite.hasPermission('users.read'), IllegalStateError);
    assert.throws(() => composite.explain('users.read'), IllegalStateError);
  });

  it('other truthy and missing answers are rejected too', () => {
    for (const answer of [1, 'yes', {}, undefined, null]) {
      const subject = { hasPermission: () => answer, grant() {}, revoke() {} } as unknown as PermissionSubject;
      assert.throws(() => Permission.check(subject, 'users.read'), IllegalStateError, String(answer));
    }
  });

  it('an explain that does not return a PermissionExplanation is rejected', () => {
    const subject = {
      hasPermission: () => true,
      explain: () => ({ allowed: true }),
      grant() {},
      revoke() {},
    } as unknown as PermissionSubject;
    assert.throws(() => Permission.explain(subject, 'users.read'), IllegalStateError);
    assert.throws(() => new CompositePermissionSubject(subject).explain('users.read'), IllegalStateError);
  });

  it('Permission.* rejects something that is not a subject', () => {
    for (const notSubject of [null, undefined, {}, 'alice']) {
      assert.throws(() => Permission.check(notSubject as never, 'users.read'), IllegalArgumentError);
      assert.throws(() => Permission.require(notSubject as never, 'users.read'), IllegalArgumentError);
    }
  });

  it('an explanation cannot be built from a non-boolean answer', () => {
    assert.throws(() => PermissionExplanation.unavailable('a.b', null, 'true' as never), IllegalArgumentError);
    assert.throws(() => PermissionExplanation.builder('a.b', null, Promise.resolve(true) as never), IllegalArgumentError);
  });
});

describe('values that are not strings', () => {
  it('are invalid nodes and rules rather than being coerced', () => {
    for (const value of [undefined, null, 42, {}, ['users'], true]) {
      assert.equal(PermissionNode.isValid(value), false);
      assert.equal(PermissionResolver.isValidPattern(value), false);
      assert.throws(() => PermissionNode.of(value as never), InvalidPermissionException);
      assert.throws(() => new MemoryPermissionSubject().hasPermission(value as never), InvalidPermissionException);
      assert.throws(() => new MemoryPermissionSubject().grant(value as never), InvalidPermissionException);
    }
  });

  it('are invalid contexts', () => {
    const subject = new MemoryPermissionSubject(['a.b']);
    for (const context of [0, 42, {}, true, ['c']]) {
      assert.equal(PermissionGrant.isValidContext(context), false);
      assert.throws(() => subject.hasPermission('a.b', context as never), IllegalArgumentError);
      assert.throws(() => subject.grant('a.b', context as never), IllegalArgumentError);
    }
  });

  it('undefined is the same as null: no context', () => {
    const subject = new MemoryPermissionSubject(['a.b']);
    assert.equal(subject.hasPermission('a.b', undefined), true);
    assert.equal(new PermissionGrant('a.b', undefined).context, null);
    assert.equal(subject.explain('a.b', undefined).context, null);
    assert.equal(Permission.check(subject, 'a.b', undefined), true);
  });

  it('a PermissionNode is accepted where a node is', () => {
    const node = PermissionNode.of('users.create');
    const subject = new MemoryPermissionSubject();
    subject.grant(node);
    assert.equal(subject.hasPermission(node), true);
    assert.equal(Permission.check(subject, node), true);
    Permission.require(subject, node);
    assert.equal(Permission.explain(subject, node).decision, Decision.PERMITTED);
    subject.revoke(node);
    assert.equal(subject.hasPermission(node), false);
  });
});

describe('PermissionNode', () => {
  it('is immutable and compares by name', () => {
    const node = PermissionNode.of('users.profile.edit');
    assert.ok(Object.isFrozen(node));
    assert.ok(Object.isFrozen(node.segments));
    assert.ok(node.equals(PermissionNode.of('users.profile.edit')));
    assert.ok(!node.equals(PermissionNode.of('users.profile')));
    assert.ok(!node.equals('users.profile.edit'));
    assert.equal(`${node}`, 'users.profile.edit');
    assert.equal(JSON.stringify({ node }), '{"node":"users.profile.edit"}');
    assert.throws(() => node.isChildOf('users.*'), InvalidPermissionException);
  });
});

describe('MemoryPermissionSubject', () => {
  it('can be created with a policy, with rules, with both, or with neither', () => {
    assert.equal(new MemoryPermissionSubject().contextPolicy, ContextPolicy.GLOBAL_FALLBACK);
    assert.equal(new MemoryPermissionSubject(['a.b']).contextPolicy, ContextPolicy.GLOBAL_FALLBACK);
    assert.equal(new MemoryPermissionSubject(ContextPolicy.EXACT).contextPolicy, ContextPolicy.EXACT);
    const both = new MemoryPermissionSubject(ContextPolicy.EXACT, new Set(['a.b', '-a.c']));
    assert.equal(both.contextPolicy, ContextPolicy.EXACT);
    assert.deepEqual(both.grants().map(String), ['a.b', '-a.c']);
    assert.throws(() => new MemoryPermissionSubject(['a.b', 'not a rule']), InvalidPermissionException);
    assert.throws(() => new MemoryPermissionSubject('a.b' as never), IllegalArgumentError);
    assert.throws(() => new MemoryPermissionSubject({} as never), IllegalArgumentError);
  });

  it('grants() is a snapshot of the grants in the order they were first granted', () => {
    const subject = new MemoryPermissionSubject();
    subject.grant('a.b');
    subject.grant('a.c', 'ctx');
    subject.grant('a.b');
    const before = subject.grants();
    subject.revoke('a.b');
    assert.deepEqual(before.map(String), ['a.b', 'a.c @ ctx']);
    assert.deepEqual(subject.grants().map(String), ['a.c @ ctx']);
    assert.ok(Object.isFrozen(before));
  });

  it('a rule and a context never collide with another rule', () => {
    const subject = new MemoryPermissionSubject(ContextPolicy.EXACT);
    subject.grant('a', 'b c');
    subject.grant('a', 'b');
    assert.equal(subject.grants().length, 2);
    assert.equal(subject.hasPermission('a', 'b c'), true);
    assert.equal(subject.hasPermission('a', 'c'), false);
    subject.revoke('a', 'b');
    assert.equal(subject.hasPermission('a', 'b c'), true);
    assert.equal(subject.hasPermission('a', 'b'), false);
  });

  it('a subclass that overrides hasPermission gets an answer-only explanation', () => {
    class Audited extends MemoryPermissionSubject {
      checks = 0;
      override hasPermission(node: string, context?: string | null): boolean {
        this.checks++;
        return node === 'always.allowed' || super.hasPermission(node, context);
      }
    }
    const subject = new Audited(['a.b']);

    const overridden = subject.explain('always.allowed');
    assert.equal(overridden.allowed, true);
    assert.equal(overridden.provenance, Provenance.UNAVAILABLE);
    assert.deepEqual(overridden.matches, []);

    const fromGrants = subject.explain('a.b');
    assert.equal(fromGrants.allowed, true);
    assert.equal(fromGrants.provenance, Provenance.UNAVAILABLE, 'the grants no longer explain the answer');
    assert.equal(subject.checks, 2, 'each explanation asked the override once');
    assert.throws(() => subject.explain('a.b', ''), IllegalArgumentError);
  });

  it('a subclass that does not override hasPermission keeps the complete explanation', () => {
    class Named extends MemoryPermissionSubject {
      name = 'alice';
    }
    assert.equal(new Named(['a.b']).explain('a.b').provenance, Provenance.COMPLETE);
  });
});

describe('PermissionExplanation', () => {
  it('reads like the Java toString', () => {
    const subject = new MemoryPermissionSubject(['students.delete']);
    subject.grant('-students.*', 'academy:123');
    assert.equal(
      subject.explain('students.delete', 'academy:123').toString(),
      'PermissionExplanation[node=students.delete, context=academy:123, allowed=false, decision=DENIED, ' +
        'provenance=COMPLETE, contextPolicy=GLOBAL_FALLBACK, decidingLayer=EXACT_CONTEXT, ' +
        'matches=[-students.* @ academy:123 (decisive), students.delete]]',
    );
    assert.equal(
      PermissionExplanation.unavailable('a.b', null, false).toString(),
      'PermissionExplanation[node=a.b, allowed=false, provenance=UNAVAILABLE]',
    );
  });

  it('is immutable', () => {
    const explanation = new MemoryPermissionSubject(['a.b']).explain('a.b');
    assert.ok(Object.isFrozen(explanation));
    assert.ok(Object.isFrozen(explanation.matches));
    assert.ok(Object.isFrozen(explanation.matches[0]));
    assert.throws(() => {
      (explanation as { allowed: boolean }).allowed = false;
    }, TypeError);
  });

  it('the builder keeps the decision consistent with the answer', () => {
    assert.equal(PermissionExplanation.builder('a.b', null, true).build().decision, Decision.PERMITTED);
    assert.equal(PermissionExplanation.builder('a.b', null, false).build().decision, null);
    assert.throws(
      () => PermissionExplanation.builder('a.b', null, true).decision(Decision.DENIED),
      IllegalArgumentError,
    );
    assert.throws(
      () => PermissionExplanation.builder('a.b', null, false).decision(Decision.PERMITTED),
      IllegalArgumentError,
    );
    assert.throws(() => PermissionExplanation.builder('a.b', null, false).decision('MAYBE' as never), IllegalArgumentError);
    assert.throws(
      () => PermissionExplanation.builder('a.b', null, false).provenance(Provenance.COMPLETE).build(),
      IllegalStateError,
      'a complete explanation of a denial needs to say which kind',
    );
    assert.throws(() => PermissionExplanation.builder('a.*', null, false), InvalidPermissionException);
    assert.throws(() => PermissionExplanation.builder('a.b', '', false), IllegalArgumentError);
  });

  it('a custom subject can report what it knows', () => {
    const backing = new MemoryPermissionSubject(['a.b']);
    const explanation = PermissionExplanation.builder('a.b', 'ctx', true)
      .provenance(Provenance.PARTIAL)
      .contextPolicy(ContextPolicy.EXACT)
      .resolutionPolicy('MY_POLICY')
      .decidingLayer(Layer.EXACT_CONTEXT)
      .match(new RuleMatch(new PermissionGrant('a.*', 'ctx'), true))
      .contribution(new Contribution(backing, true, backing.explain('a.b')))
      .build();
    assert.equal(explanation.resolutionPolicy, 'MY_POLICY');
    assert.equal(explanation.matches[0]?.wildcard, true);
    assert.equal(explanation.matches[0]?.deny, false);
    assert.equal(explanation.contributions[0]?.source, backing);
    assert.throws(() => new RuleMatch({ rule: 'a.b', context: null } as never, true), IllegalArgumentError);
    assert.throws(() => new Contribution(null as never, true, explanation), IllegalArgumentError);
    assert.throws(() => new Contribution(backing, true, {} as never), IllegalArgumentError);
  });
});

describe('errors', () => {
  it('permission errors share a base type; argument and state errors do not', () => {
    const invalid = new InvalidPermissionException('bad node');
    assert.ok(invalid instanceof PernoramaException);
    assert.ok(invalid instanceof Error);
    assert.equal(invalid.name, 'InvalidPermissionException');
    assert.equal(invalid.message, "Invalid permission: 'bad node'");
    assert.equal(invalid.value, 'bad node');
    assert.equal(new InvalidPermissionException(null).message, "Invalid permission: 'null'");

    assert.ok(!(new IllegalArgumentError('x') instanceof PernoramaException));
    assert.ok(!(new IllegalStateError('x') instanceof PernoramaException));
    assert.ok(!(new UnsupportedOperationError('x') instanceof PernoramaException));
  });

  it('a denial names the node and context, and does not serialize the subject', () => {
    const subject = new MemoryPermissionSubject(['secret.grant']);
    let denied: unknown;
    try {
      Permission.require(subject, 'students.delete', 'academy:123');
    } catch (error) {
      denied = error;
    }
    assert.ok(denied instanceof PermissionDeniedException);
    assert.ok(denied instanceof PernoramaException);
    assert.equal(denied.message, 'Permission denied: students.delete in context academy:123');
    assert.equal(denied.requiredPermission, 'students.delete');
    assert.equal(denied.context, 'academy:123');
    assert.equal(denied.subject, subject);
    assert.ok(!JSON.stringify(denied).includes('subject'));
    assert.ok(!Object.keys(denied).includes('subject'));

    assert.throws(() => Permission.require(subject, 'students.delete'), {
      message: 'Permission denied: students.delete',
    });
  });
});

describe('ContextPolicy and Pernorama', () => {
  it('there are exactly two policies, compared by identity', () => {
    assert.equal(ContextPolicy.valueOf('EXACT'), ContextPolicy.EXACT);
    assert.equal(ContextPolicy.valueOf('GLOBAL_FALLBACK'), ContextPolicy.GLOBAL_FALLBACK);
    assert.throws(() => ContextPolicy.valueOf('exact'), IllegalArgumentError);
    assert.equal(String(ContextPolicy.EXACT), 'EXACT');
    assert.equal(JSON.stringify([ContextPolicy.EXACT]), '["EXACT"]');
    assert.throws(() => new (ContextPolicy as never as new () => ContextPolicy)(), TypeError);
  });

  it('permits and explain only accept PermissionGrant instances', () => {
    const lookalike = [{ rule: '*', context: null }] as never;
    assert.throws(() => ContextPolicy.EXACT.permits(lookalike, 'a.b'), IllegalArgumentError);
    assert.throws(() => ContextPolicy.EXACT.explain(lookalike, 'a.b'), IllegalArgumentError);
    assert.throws(() => ContextPolicy.EXACT.permits(null as never, 'a.b'), IllegalArgumentError);
  });

  it('an instance hands its policy to what it creates', () => {
    assert.equal(Pernorama.builder().build().contextPolicy, ContextPolicy.GLOBAL_FALLBACK);
    assert.equal(Pernorama.create().contextPolicy, ContextPolicy.GLOBAL_FALLBACK);
    const exact = Pernorama.create({ contextPolicy: ContextPolicy.EXACT });
    assert.equal(exact.newSubject().contextPolicy, ContextPolicy.EXACT);
    assert.equal(exact.newSubject(['a.b']).hasPermission('a.b', 'ctx'), false);
    assert.equal(String(exact), 'Pernorama[contextPolicy=EXACT]');
    assert.throws(() => Pernorama.builder().contextPolicy('EXACT' as never), IllegalArgumentError);
  });
});

describe('CompositePermissionSubject', () => {
  it('takes its sources as arguments or as one iterable, and copies them', () => {
    const a = new MemoryPermissionSubject(['a.a']);
    const b = new MemoryPermissionSubject(['b.b']);
    const list = [a, b];
    const fromList = new CompositePermissionSubject(list);
    list.pop();
    assert.equal(fromList.sources.length, 2);
    assert.equal(new CompositePermissionSubject(a, b).hasPermission('b.b'), true);
    assert.equal(new CompositePermissionSubject(new Set([a])).hasPermission('b.b'), false);
    assert.equal(new CompositePermissionSubject().hasPermission('a.a'), false);
    assert.equal(new CompositePermissionSubject(a).sources[0], a);
    assert.ok(Object.isFrozen(fromList.sources));
    assert.throws(() => new CompositePermissionSubject(a, null as never), IllegalArgumentError);
    assert.throws(() => new CompositePermissionSubject([a, {} as never]), IllegalArgumentError);
  });

  it('stops at the first source that permits', () => {
    let asked = 0;
    const counting: PermissionSubject = {
      hasPermission: () => {
        asked++;
        return false;
      },
      grant() {},
      revoke() {},
    };
    const composite = new CompositePermissionSubject(new MemoryPermissionSubject(['a.b']), counting);
    assert.equal(composite.hasPermission('a.b'), true);
    assert.equal(asked, 0);
    assert.equal(composite.hasPermission('a.c'), false);
    assert.equal(asked, 1);
  });
});
