import { IllegalArgumentError } from '../error/errors.js';
import { isBlank, isWhitespace } from '../internal/java-strings.js';

/** Validation shared by `Role` and `RoleGroup` ids. */
export function requireValidId(id: unknown, what: string): string {
  if (typeof id !== 'string' || isBlank(id)) {
    throw new IllegalArgumentError(`${what} must not be blank`);
  }
  if (isWhitespace(id.charAt(0)) || isWhitespace(id.charAt(id.length - 1))) {
    throw new IllegalArgumentError(`${what} must not have leading or trailing whitespace: '${id}'`);
  }
  return id;
}
