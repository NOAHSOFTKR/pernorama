package pernorama.bench;

import pernorama.permission.ContextPolicy;
import pernorama.role.PermissionResolutionPolicy;
import pernorama.role.Role;
import pernorama.role.RoleAssignments;
import pernorama.subject.MemoryPermissionSubject;
import pernorama.subject.PermissionSubject;

/**
 * A plain, dependency-free timing harness for the {@code hasPermission}
 * check path — not a JUnit test, and not a substitute for JMH. Run it with
 * {@code ./gradlew checkPathBenchmark} on two commits and compare the
 * ns/op it prints; differences within a few percent are noise.
 *
 * <p>Workload, per measured round, in context {@code ctx:1}:
 * <ul>
 *   <li>a {@link MemoryPermissionSubject} under
 *       {@link ContextPolicy#GLOBAL_FALLBACK} holding 400 grants
 *       ({@code mod<i>.*} without a context and {@code -mod<i>.delete} in
 *       one of five contexts, for 200 modules);</li>
 *   <li>a role-assignment subject under
 *       {@link PermissionResolutionPolicy#DENY_OVERRIDES} holding 10 roles
 *       of 20 rules each, half of them assigned in {@code ctx:1};</li>
 *   <li>four nodes cycled: permitted, denied, not covered, and a deep
 *       node under a wildcard.</li>
 * </ul>
 * {@value #WARMUP_ROUNDS} warm-up rounds, then {@value #MEASURED_ROUNDS}
 * measured rounds of {@value #CHECKS_PER_ROUND} checks per subject. The
 * JDK and these settings are printed with the results.
 */
public final class CheckPathBenchmark {

    private static final int WARMUP_ROUNDS = 5;
    private static final int MEASURED_ROUNDS = 10;
    private static final int CHECKS_PER_ROUND = 200_000;
    private static final String CONTEXT = "ctx:1";
    private static final String[] NODES = {"mod5.read", "mod150.delete", "nope.read", "mod199.x.y"};

    private CheckPathBenchmark() {
    }

    public static void main(String[] args) {
        MemoryPermissionSubject grants = new MemoryPermissionSubject(ContextPolicy.GLOBAL_FALLBACK);
        for (int i = 0; i < 200; i++) {
            grants.grant("mod" + i + ".*");
            grants.grant("-mod" + i + ".delete", "ctx:" + (i % 5));
        }

        RoleAssignments<String> assignments = new RoleAssignments<>();
        for (int i = 0; i < 10; i++) {
            Role.Builder role = Role.builder("role" + i);
            for (int j = 0; j < 20; j++) {
                role.permission("mod" + (i * 20 + j) + ".*");
            }
            assignments.assign("user", role.build(), i % 2 == 0 ? null : CONTEXT);
        }
        PermissionSubject roles = assignments.subject("user", PermissionResolutionPolicy.DENY_OVERRIDES);

        System.out.printf("JDK %s (%s), %d warm-up + %d measured rounds of %d checks%n",
                Runtime.version(), System.getProperty("java.vm.name"),
                WARMUP_ROUNDS, MEASURED_ROUNDS, CHECKS_PER_ROUND);

        long sink = 0;
        double grantsTotal = 0;
        double rolesTotal = 0;
        for (int round = 0; round < WARMUP_ROUNDS + MEASURED_ROUNDS; round++) {
            long start = System.nanoTime();
            for (int i = 0; i < CHECKS_PER_ROUND; i++) {
                sink += grants.hasPermission(NODES[i & 3], CONTEXT) ? 1 : 0;
            }
            double grantsNs = (System.nanoTime() - start) / (double) CHECKS_PER_ROUND;

            start = System.nanoTime();
            for (int i = 0; i < CHECKS_PER_ROUND; i++) {
                sink += roles.hasPermission(NODES[i & 3], CONTEXT) ? 1 : 0;
            }
            double rolesNs = (System.nanoTime() - start) / (double) CHECKS_PER_ROUND;

            if (round >= WARMUP_ROUNDS) {
                grantsTotal += grantsNs;
                rolesTotal += rolesNs;
            }
        }
        System.out.printf("MemoryPermissionSubject (400 grants): %.0f ns/op%n", grantsTotal / MEASURED_ROUNDS);
        System.out.printf("RoleAssignments subject (10 roles):   %.0f ns/op%n", rolesTotal / MEASURED_ROUNDS);
        System.out.println("(checksum " + sink + ")");
    }
}
