package pernorama.fixture;

/**
 * Overrides {@link BaseDocumentService#read()} without redeclaring
 * {@code @Perm}. Per the documented resolution rule, the override does
 * not inherit the superclass method's permission, so this method
 * requires no permission at all.
 */
public class OverridingDocumentService extends BaseDocumentService {

    @Override
    public void read() {
    }
}
