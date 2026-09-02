package pernorama.fixture;

import pernorama.annotation.Perm;
import pernorama.annotation.PermGroup;

@PermGroup("docs")
public class BaseDocumentService {

    @Perm("read")
    public void read() {
    }

    public void ping() {
    }
}
