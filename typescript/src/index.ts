export { Pernorama, PernoramaBuilder, type PernoramaOptions } from './pernorama.js';

export {
  AuthorizationUnavailableException,
  type AuthorizationUnavailableReason,
  IllegalArgumentError,
  IllegalStateError,
  InvalidPermissionException,
  PermissionDeniedException,
  PernoramaException,
  UnsupportedOperationError,
} from './error/errors.js';

export { ContextPolicy } from './permission/context-policy.js';
export { Decision } from './permission/decision.js';
export { Permission } from './permission/permission.js';
export {
  Contribution,
  Layer,
  PermissionExplanation,
  PermissionExplanationBuilder,
  Provenance,
  RuleMatch,
} from './permission/permission-explanation.js';
export { PermissionGrant } from './permission/permission-grant.js';
export { PermissionNode } from './permission/permission-node.js';
export { PermissionResolver } from './permission/permission-resolver.js';

export { CompositePermissionSubject } from './subject/composite-permission-subject.js';
export { MemoryPermissionSubject } from './subject/memory-permission-subject.js';
export { isPermissionSubject, type PermissionSubject } from './subject/permission-subject.js';

export { PermissionResolutionPolicy } from './role/permission-resolution-policy.js';
export { Role, RoleBuilder } from './role/role.js';
export { RoleAssignment, RoleAssignmentResult, RoleAssignmentStatus } from './role/role-assignment.js';
export { RoleAssignmentDecision, RoleAssignmentPolicy } from './role/role-assignment-policy.js';
export {
  type AsyncRoleAssignmentStore,
  MemoryRoleAssignmentStore,
  type RoleAssignmentStore,
} from './role/role-assignment-store.js';
export { AsyncRoleAssignments, RoleAssignments } from './role/role-assignments.js';
export { RoleGroup, RoleGroupBuilder } from './role/role-group.js';
