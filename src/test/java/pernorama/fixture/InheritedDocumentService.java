package pernorama.fixture;

/**
 * Does not override {@link BaseDocumentService#read()} at all, so
 * resolving it should find {@code @Perm}/{@code @PermGroup} on
 * {@link BaseDocumentService}, its true declaring class.
 */
public class InheritedDocumentService extends BaseDocumentService {
}
