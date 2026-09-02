package pernorama.fixture;

/**
 * Overrides {@link Pingable#ping()} without redeclaring {@code @Perm},
 * so it requires no permission, same rule as a class override.
 */
public class OverridingPingableService implements Pingable {

    @Override
    public void ping() {
    }
}
