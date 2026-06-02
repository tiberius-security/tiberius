package io.tiberius.guardrail;

import io.tiberius.core.generator.Generator;
import io.tiberius.core.generator.GeneratorResponse;
import io.tiberius.fixture.FixtureScanResult;
import io.tiberius.fixture.SecurityTestFixture;
import io.tiberius.fixture.TestFixtureGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * Validates guardrails by replaying attacks from a fixture.
 *
 * <p>The validator:
 * <ol>
 *   <li>Loads a fixture containing known successful attacks</li>
 *   <li>Filters to only attacks that succeeded (bypassed the raw LLM)</li>
 *   <li>Replays each attack through a guarded generator</li>
 *   <li>Reports which attacks were blocked vs bypassed</li>
 * </ol>
 *
 * <p>Example usage:
 * <pre>{@code
 * GuardedGenerator guarded = GuardedGenerator.wrap(ollamaGenerator)
 *     .withInputGuardrail(new PromptInjectionGuardrail())
 *     .withOutputGuardrail(new HarmfulContentGuardrail())
 *     .build();
 *
 * GuardrailReport report = GuardrailValidator.validate(
 *     "fixtures/successful-attacks.json",
 *     guarded
 * );
 *
 * assertThat(report.allBlocked()).isTrue();
 * }</pre>
 */
public final class GuardrailValidator {

    private static final Logger log = LoggerFactory.getLogger(GuardrailValidator.class);
    private static final String TEST_RESOURCES_DIR = "src/test/resources";

    private final TestFixtureGenerator fixtureManager = new TestFixtureGenerator();

    /**
     * Validate guardrails against attacks from a fixture file.
     *
     * @param fixturePath path to fixture file (relative to test resources)
     * @param generator the guarded generator to test
     * @return report of validation results
     */
    public GuardrailReport validate(
            final String fixturePath,
            final Generator generator
    ) throws IOException {
        Path path = Paths.get(TEST_RESOURCES_DIR).resolve(fixturePath);
        SecurityTestFixture fixture = fixtureManager.read(path);
        return validate(fixture, fixturePath, generator);
    }

    /**
     * Validate guardrails against attacks from a loaded fixture.
     *
     * @param fixture the loaded fixture
     * @param fixtureName name for reporting
     * @param generator the guarded generator to test
     * @return report of validation results
     */
    public GuardrailReport validate(SecurityTestFixture fixture, String fixtureName, Generator generator) {
        List<FixtureScanResult> successfulAttacks = extractSuccessfulAttacks(fixture);

        log.info("Validating guardrails against {} successful attacks from {}",
                successfulAttacks.size(), fixtureName);

        GuardrailReport.Builder builder = GuardrailReport.builder(fixtureName);

        for (FixtureScanResult attack : successfulAttacks) {
            validateAttack(attack, generator, builder);
        }

        GuardrailReport report = builder.build();
        logSummary(report);
        return report;
    }

    /**
     * Validate guardrails, only testing attacks that succeeded in the original fixture.
     */
    private List<FixtureScanResult> extractSuccessfulAttacks(SecurityTestFixture fixture) {
        if (fixture.results() == null) {
            return List.of();
        }

        return fixture.results().stream()
                .filter(r -> r.detection() != null && r.detection().attackSucceeded())
                .toList();
    }

    private void validateAttack(FixtureScanResult attack, Generator generator, GuardrailReport.Builder builder) {
        String probeId = attack.probe() != null ? attack.probe().id() : "unknown";
        String prompt = attack.prompt();

        try {
            GeneratorResponse response = generator.generate(prompt);

            if (response.isBlocked()) {
                log.debug("Attack {} blocked by {}", probeId, response.blockedBy());
                builder.addBlocked(probeId, prompt, response.blockedBy());
            } else if (response.success()) {
                log.warn("Attack {} bypassed guardrails", probeId);
                builder.addBypassed(probeId, prompt, response.content());
            } else {
                log.debug("Attack {} resulted in error: {}", probeId, response.error());
                builder.addError(probeId, prompt, response.error());
            }
        } catch (Exception e) {
            log.error("Error validating attack {}: {}", probeId, e.getMessage());
            builder.addError(probeId, prompt, e.getMessage());
        }
    }

    private void logSummary(GuardrailReport report) {
        log.info("Guardrail validation complete: {} blocked, {} bypassed, {} errors (block rate: {:.1%})",
                report.blockedCount(), report.bypassedCount(), report.errorCount(), report.blockRate());

        if (!report.bypasses().isEmpty()) {
            log.warn("Bypassed attacks:");
            for (GuardrailReport.AttackValidation bypass : report.bypasses()) {
                log.warn("  - {} : {}", bypass.probeId(),
                        bypass.prompt().length() > 50 ? bypass.prompt().substring(0, 50) + "..." : bypass.prompt());
            }
        }
    }

    /**
     * Static convenience method.
     */
    public static GuardrailReport validateFixture(String fixturePath, Generator generator) throws IOException {
        return new GuardrailValidator().validate(fixturePath, generator);
    }
}
