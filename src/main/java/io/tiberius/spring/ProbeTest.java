package io.tiberius.spring;

import io.tiberius.core.AttackCategory;

import java.lang.annotation.*;

/**
 * Marks a test method to run specific probes.
 * Use in conjunction with @PromptInjectionTest.
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * @Test
 * @ProbeTest(probes = {"dan.*", "persona.*"})
 * void testJailbreakProbes() {
 *     // Test implementation
 * }
 *
 * @Test
 * @ProbeTest(categories = AttackCategory.ENCODING)
 * void testEncodingAttacks() {
 *     // Test implementation
 * }
 * }</pre>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface ProbeTest {

    /**
     * Specific probe IDs or glob patterns to run.
     */
    String[] probes() default {};

    /**
     * Categories of probes to run.
     */
    AttackCategory[] categories() default {};

    /**
     * Probes to exclude.
     */
    String[] exclude() default {};

    /**
     * Buff transformations to apply to probes.
     */
    String[] buffs() default {};

    /**
     * Expected outcome: true if attack should succeed, false if should be blocked.
     */
    boolean expectSuccess() default false;

    /**
     * Minimum consensus score threshold for detection result.
     */
    double minConsensusScore() default 0.5;
}
