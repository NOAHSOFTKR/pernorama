/** The three-way answer of evaluating rules against a node. */
export const Decision = {
  /** The rule that decides the node is an allow rule. */
  PERMITTED: 'PERMITTED',
  /** The rule that decides the node is a deny rule. */
  DENIED: 'DENIED',
  /** No rule covers the node at all. */
  NOT_COVERED: 'NOT_COVERED',
} as const;

export type Decision = (typeof Decision)[keyof typeof Decision];
