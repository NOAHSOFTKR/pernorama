package pernorama.fixture;

import pernorama.annotation.Perm;
import pernorama.annotation.PermGroup;

@PermGroup("users")
public class UserPermissions {

    @Perm("create")
    public void create() {
    }

    @Perm("delete")
    public void delete() {
    }
}
