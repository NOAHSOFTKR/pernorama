package pernorama.fixture;

import pernorama.annotation.Perm;

public class UserService {

    private boolean created;
    private boolean pinged;

    @Perm("users.create")
    public void createUser() {
        created = true;
    }

    public void ping() {
        pinged = true;
    }

    public boolean isCreated() {
        return created;
    }

    public boolean isPinged() {
        return pinged;
    }
}
