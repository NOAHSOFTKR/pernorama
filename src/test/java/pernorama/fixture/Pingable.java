package pernorama.fixture;

import pernorama.annotation.Perm;
import pernorama.annotation.PermGroup;

@PermGroup("io")
public interface Pingable {

    @Perm("ping")
    default void ping() {
    }
}
