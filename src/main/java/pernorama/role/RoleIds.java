package pernorama.role;

/** Validation shared by {@link Role} and {@link RoleGroup} ids. */
final class RoleIds {

    private RoleIds() {
    }

    static String requireValid(String id, String what) {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException(what + " must not be blank");
        }
        if (!id.equals(id.strip())) {
            throw new IllegalArgumentException(what + " must not have leading or trailing whitespace: '" + id + "'");
        }
        return id;
    }
}
