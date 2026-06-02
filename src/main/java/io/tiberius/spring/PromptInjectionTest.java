package io.tiberius.spring;

import io.tiberius.core.AttackCategory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestExecutionListeners;

import java.lang.annotation.*;

/**
 * Marks a test class or method as an LLM prompt injection test.
 * This annotation enables the Tiberius testing framework for security testing.
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * @PromptInjectionTest
 * @SpringBootTest
 * class MyLLMSecurityTest {
 *
 *     @Autowired
 *     private TiberiusScanner scanner;
 *
 *     @Test
 *     @ProbeTest(probes = "dan.*")
 *     void testDanJailbreaks() {
 *         var report = scanner.scan();
 *         assertThat(report.successRate()).isLessThan(5.0);
 *     }
 * }
 * }</pre>
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@TestExecutionListeners(
        listeners = PromptInjectionTestExecutionListener.class,
        mergeMode = TestExecutionListeners.MergeMode.MERGE_WITH_DEFAULTS
)
public @interface PromptInjectionTest {

    /**
     * Categories of attacks to test. Default includes all categories.
     */
    AttackCategory[] categories() default {};

    /**
     * Glob patterns for specific probes to include.
     * Example: "dan.*", "encoding.*"
     */
    String[] probes() default {};

    /**
     * Glob patterns for probes to exclude.
     */
    String[] excludeProbes() default {};

    /**
     * Minimum severity level for probes (1-5).
     */
    int minSeverity() default 1;

    /**
     * Generator ID to use for testing.
     * If empty, uses the configured default or mock generator.
     */
    String generator() default "";

    /**
     * Detector ID to use for evaluation.
     * If empty, uses the composite default detector.
     */
    String detector() default "";

    /**
     * Maximum acceptable attack success rate (percentage).
     * Test fails if success rate exceeds this threshold.
     */
    double maxSuccessRate() default 0.0;

    /**
     * Whether to fail fast on first successful attack.
     */
    boolean failFast() default false;

    /**
     * Tags to filter probes.
     */
    String[] tags() default {};

    /**
     * Description of the test for reporting.
     */
    String description() default "";
}
