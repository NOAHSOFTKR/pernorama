package pernorama.fixture;

import pernorama.annotation.Perm;
import pernorama.annotation.PermGroup;

public class OuterService {

    @PermGroup("nested")
    public static class NestedService {

        @Perm("create")
        public void create() {
        }
    }
}
