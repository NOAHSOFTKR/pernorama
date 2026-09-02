package pernorama.fixture;

import pernorama.annotation.Perm;
import pernorama.annotation.PermGroup;

/**
 * Overrides {@link BaseDocumentService#read()} and redeclares
 * {@code @Perm} under its own, different {@code @PermGroup}, to show
 * that an overriding method resolves against its own declaring class,
 * not its superclass's.
 */
@PermGroup("archive")
public class RedeclaringDocumentService extends BaseDocumentService {

    @Override
    @Perm("readArchived")
    public void read() {
    }
}
