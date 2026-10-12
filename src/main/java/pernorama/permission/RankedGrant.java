package pernorama.permission;

/**
 * A grant that covers the node being explained, with its
 * {@link PermissionResolver#rank rank} and whether it was reached by
 * falling back to the global grants. Collected while a check is
 * evaluated, so an explanation is built from the very ranks that decided
 * it rather than from a second evaluation.
 */
record RankedGrant(PermissionGrant grant, boolean fallback, int rank) {
}
