package io.tiberius.junit;

import io.tiberius.core.AttackCategory;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.lang.annotation.*;

/**
 * JUnit 5 parameterized test source that provides probes as arguments.
 * Use with @ParameterizedTest to run tests against multiple probes.
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * @ParameterizedTest
 * @ProbeSource(categories = AttackCategory.JAILBREAK)
 * void testJailbreakProbes(Probe probe, TiberiusScanner scanner) {
 *     ScanResult result = scanner.runProbe(probe);
 *     assertFalse(result.attackSucceeded(), "Jailbreak should be blocked: " + probe.getId());
 * }
 * }</pre>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@ArgumentsSource(ProbeArgumentsProvider.class)
public @interface ProbeSource {

    /**
     * Probe ID patterns to include (glob syntax).
     */
    String[] patterns() default {"*"};

    /**
     * Attack categories to include.
     */
    AttackCategory[] categories() default {};

    /**
     * Minimum severity level.
     */
    int minSeverity() default 1;

    /**
     * Maximum number of probes to provide.
     */
    int limit() default 100;

    /**
     * Patterns to exclude.
     */
    String[] exclude() default {};
}
