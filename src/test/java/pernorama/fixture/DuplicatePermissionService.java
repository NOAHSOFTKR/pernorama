package pernorama.fixture;

import pernorama.annotation.Perm;
import pernorama.annotation.PermGroup;

/** Two methods intentionally guarded by the same permission node. */
@PermGroup("users")
public class DuplicatePermissionService {

    @Perm("delete")
    public void delete() {
    }

    @Perm("delete")
    public void bulkDelete() {
    }
}
