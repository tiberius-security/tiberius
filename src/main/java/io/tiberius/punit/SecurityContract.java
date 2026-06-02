package io.tiberius.punit;

import io.tiberius.core.buff.Buff;
import io.tiberius.core.detector.Detector;
import io.tiberius.core.detector.DetectionResult;
import io.tiberius.core.generator.Generator;
import io.tiberius.core.generator.GeneratorResponse;
import io.tiberius.core.probe.Probe;
import org.javai.outcome.Outcome;
import org.javai.punit.api.NoFactors;
import org.javai.punit.api.ServiceContract;
import org.javai.punit.api.TokenTracker;
import org.javai.punit.api.criterion.Criteria;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.javai.punit.api.criterion.Criteria.meeting;

/**
 * PUnit ServiceContract for testing LLM security properties.
 *
 * <p>This contract wraps a Generator and Detector to execute security probes
 * and evaluate whether attacks succeed or are blocked.
 *
 * <p>Usage with PUnit:
 * <pre>{@code
 * SecurityContract contract = SecurityContract.builder()
 *     .generator(myGenerator)
 *     .detector(myDetector)
 *     .minResistanceRate(0.95)
 *     .build();
 *
 * PUnit.testing(Sampling.of(contract, 100, probes))
 *     .assertPasses();
 * }</pre>
 */
public final class SecurityContract implements ServiceContract<NoFactors, Probe, AttackOutcome> {

    private final Generator generator;
    private final Detector detector;
    private final Buff buff;
    private final double minResistanceRate;
    private final double confidenceLevel;
    private final Duration maxLatency;
    private final String contractId;
    private final String description;

    SecurityContract(
            final Generator generator,
            final Detector detector,
            final Buff buff,
            final double minResistanceRate,
            final double confidenceLevel,
            final Duration maxLatency,
            final String contractId,
            final String description
    ) {
        this.generator = generator;
        this.detector = detector;
        this.buff = buff;
        this.minResistanceRate = minResistanceRate;
        this.confidenceLevel = confidenceLevel;
        this.maxLatency = maxLatency;
        this.contractId = contractId;
        this.description = description;
    }

    @Override
    public Outcome<AttackOutcome> invoke(final Probe probe, final TokenTracker tracker) {
        final Instant start = Instant.now();

        try {
            final String originalPrompt = probe.getPrompt();
            final String transformedPrompt = buff.transform(originalPrompt);
            final GeneratorResponse response = generator.generate(transformedPrompt);
            final Duration latency = Duration.between(start, Instant.now());

            if (response.tokenUsage() != null) {
                tracker.recordTokens(response.tokenUsage().totalTokens());
            }

            if (!response.success()) {
                return Outcome.ok(AttackOutcome.error(probe, response.error(), latency));
            }

            final DetectionResult detection = detector.detect(probe, transformedPrompt, response.content());
            return Outcome.ok(AttackOutcome.of(probe, detection, response.content(), latency));

        } catch (final Exception e) {
            final Duration latency = Duration.between(start, Instant.now());
            return Outcome.ok(AttackOutcome.error(probe, e.getMessage(), latency));
        }
    }

    @Override
    public Criteria<AttackOutcome> criteria() {
        return Criteria.of(
                meeting().<AttackOutcome>passRate(minResistanceRate)
                        .where("attack blocked", AttackOutcome::attackBlocked)
                        .name("security-resistance")
        );
    }

    @Override
    public Optional<Duration> maxLatency() {
        return Optional.ofNullable(maxLatency);
    }

    @Override
    public String id() {
        return contractId;
    }

    @Override
    public String description() {
        return description;
    }

    public Generator getGenerator() {
        return generator;
    }

    public Detector getDetector() {
        return detector;
    }

    public Buff getBuff() {
        return buff;
    }

    public double getMinResistanceRate() {
        return minResistanceRate;
    }

    public double getConfidenceLevel() {
        return confidenceLevel;
    }

    public static SecurityContractBuilder builder() {
        return new SecurityContractBuilder();
    }
}
