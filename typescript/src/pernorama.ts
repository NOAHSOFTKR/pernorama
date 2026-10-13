import { IllegalArgumentError } from './error/errors.js';
import { ContextPolicy } from './permission/context-policy.js';
import { MemoryPermissionSubject } from './subject/memory-permission-subject.js';

/** The settings of a {@link Pernorama} instance. */
export interface PernoramaOptions {
  /**
   * The policy deciding whether a grant without a context also applies
   * inside one. Defaults to `ContextPolicy.GLOBAL_FALLBACK`.
   */
  readonly contextPolicy?: ContextPolicy;
}

/**
 * The settings an application chooses once for all of its permission
 * checks, and the factory for the components that apply them:
 *
 * ```ts
 * const pernorama = Pernorama.builder()
 *   .contextPolicy(ContextPolicy.EXACT)
 *   .build();
 *
 * const user = pernorama.newSubject();
 * ```
 *
 * Today the only setting is the {@link ContextPolicy}, which decides
 * whether a permission granted without a context also applies inside one.
 * It is instance-wide on purpose: individual permissions never carry their
 * own policy, and an application that needs different semantics for
 * different domains uses one instance per domain.
 *
 * Pernorama never keeps an instance of its own; the application creates
 * one and passes it where it is needed. Everything created through an
 * instance uses its settings.
 *
 * Immutable.
 */
export class Pernorama {
  /** The policy deciding which grants apply when a check names a context. */
  readonly contextPolicy: ContextPolicy;

  private constructor(contextPolicy: ContextPolicy) {
    this.contextPolicy = contextPolicy;
    Object.freeze(this);
  }

  /**
   * Starts building an instance. Every setting has a default, so
   * `Pernorama.builder().build()` is a complete configuration.
   */
  static builder(): PernoramaBuilder {
    return new PernoramaBuilder((contextPolicy) => new Pernorama(contextPolicy));
  }

  /** `Pernorama.builder()` with the given settings, built. */
  static create(options: PernoramaOptions = {}): Pernorama {
    const builder = Pernorama.builder();
    if (options.contextPolicy !== undefined) {
      builder.contextPolicy(options.contextPolicy);
    }
    return builder.build();
  }

  /**
   * A new in-memory subject using this instance's settings, optionally
   * pre-granted with the given rules, without a context.
   *
   * @throws InvalidPermissionException if any rule is not a valid rule
   */
  newSubject(initialPermissions?: Iterable<string>): MemoryPermissionSubject {
    return new MemoryPermissionSubject(this.contextPolicy, initialPermissions);
  }

  toString(): string {
    return `Pernorama[contextPolicy=${this.contextPolicy}]`;
  }
}

/** Builder for {@link Pernorama}; get one from `Pernorama.builder`. */
export class PernoramaBuilder {
  readonly #create: (contextPolicy: ContextPolicy) => Pernorama;
  #contextPolicy: ContextPolicy = ContextPolicy.GLOBAL_FALLBACK;

  /** @internal */
  constructor(create: (contextPolicy: ContextPolicy) => Pernorama) {
    this.#create = create;
  }

  /**
   * Sets the policy deciding whether a grant without a context also
   * applies inside one. Defaults to `ContextPolicy.GLOBAL_FALLBACK`.
   */
  contextPolicy(contextPolicy: ContextPolicy): this {
    if (!(contextPolicy instanceof ContextPolicy)) {
      throw new IllegalArgumentError('contextPolicy must be a ContextPolicy');
    }
    this.#contextPolicy = contextPolicy;
    return this;
  }

  /** Builds the instance. */
  build(): Pernorama {
    return this.#create(this.#contextPolicy);
  }
}
