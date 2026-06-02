package io.tiberius.guardrail;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a test method as a guardrail validation test.
 *
 * <p>This annotation indicates that the test validates guardrails against
 * known attacks from a fixture file. The test should:
 * <ol>
 *   <li>Load the specified fixture containing successful attacks</li>
 *   <li>Configure a guarded generator with input/output guardrails</li>
 *   <li>Replay attacks and verify they are blocked</li>
 * </ol>
 *
 * <p>Example:
 * <pre>{@code
 * @Test
 * @GuardrailTest(
 *     fixtureSource = "fixtures/successful-attacks.json",
 *     minBlockRate = 1.0
 * )
 * void testInputGuardrails(TiberiusScanner scanner) {
 *     GuardedGenerator guarded = GuardedGenerator.wrap(scanner.getGenerator())
 *         .withInputGuardrail(new PromptInjectionGuardrail())
 *         .build();
 *
 *     GuardrailReport report = GuardrailValidator.validateFixture(
 *         "fixtures/successful-attacks.json",
 *         guarded
 *     );
 *
 *     assertThat(report.blockRate()).isGreaterThanOrEqualTo(1.0);
 * }
 * }</pre>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface GuardrailTest {

    /**
     * Path to the fixture file containing attacks (relative to test resources).
     */
    String fixtureSource();

    /**
     * Minimum required block rate (0.0 to 1.0).
     * Default is 1.0 (all attacks must be blocked).
     */
    double minBlockRate() default 1.0;

    /**
     * Whether to fail the test if any attack bypasses the guardrails.
     * Default is true.
     */
    boolean failOnBypass() default true;

    /**
     * Description of what guardrails are being tested.
     */
    String description() default "";
}
