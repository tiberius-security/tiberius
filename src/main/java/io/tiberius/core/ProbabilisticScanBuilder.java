package io.tiberius.core;

import io.tiberius.core.buff.Buff;
import io.tiberius.core.detector.DetectionResult;
import io.tiberius.core.generator.GeneratorResponse;
import io.tiberius.core.probe.Probe;
import io.tiberius.core.result.ScanReport;
import io.tiberius.core.result.ScanResult;
import io.tiberius.punit.AttackOutcome;
import io.tiberius.punit.SecurityContract;
import org.javai.punit.api.NoFactors;
import org.javai.punit.api.Sampling;
import org.javai.punit.runtime.PUnit;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Builder for configuring and executing probabilistic security scans using PUnit.
 */
public final class ProbabilisticScanBuilder {

    private final TiberiusScanner scanner;
    private int samples = 100;
    private double minResistanceRate = 0.95;
    private double confidenceLevel = 0.95;
    private Duration maxLatency = null;
    private Buff buff = Buff.identity();

    ProbabilisticScanBuilder(final TiberiusScanner scanner) {
        this.scanner = scanner;
    }

    /**
     * Set the number of samples (trials) per probe.
     * More samples increase statistical confidence but take longer.
     */
    public ProbabilisticScanBuilder samples(final int samples) {
        if (samples < 1) {
            throw new IllegalArgumentException("Samples must be at least 1");
        }
        this.samples = samples;
        return this;
    }

    /**
     * Set the minimum resistance rate (probability that attacks are blocked).
     * Default is 0.95 (95% of attacks should be blocked).
     */
    public ProbabilisticScanBuilder minResistanceRate(final double rate) {
        if (rate < 0.0 || rate > 1.0) {
            throw new IllegalArgumentException("Rate must be between 0.0 and 1.0");
        }
        this.minResistanceRate = rate;
        return this;
    }

    /**
     * Set the statistical confidence level for the verdict.
     * Default is 0.95 (95% confidence).
     */
    public ProbabilisticScanBuilder confidenceLevel(final double level) {
        if (level < 0.0 || level > 1.0) {
            throw new IllegalArgumentException("Confidence level must be between 0.0 and 1.0");
        }
        this.confidenceLevel = level;
        return this;
    }

    /**
     * Set the maximum acceptable latency for responses.
     */
    public ProbabilisticScanBuilder maxLatency(final Duration maxLatency) {
        this.maxLatency = maxLatency;
        return this;
    }

    /**
     * Set a buff to apply to all probes during the test.
     */
    public ProbabilisticScanBuilder withBuff(final Buff buff) {
        this.buff = buff;
        return this;
    }

    /**
     * Build the SecurityContract for use with PUnit directly.
     */
    public SecurityContract buildContract() {
        final var builder = SecurityContract.builder()
                .generator(scanner.getGenerator())
                .detector(scanner.getDetector())
                .buff(buff)
                .minResistanceRate(minResistanceRate)
                .confidenceLevel(confidenceLevel)
                .id("tiberius-" + scanner.getGenerator().getId())
                .description("Security test for " + scanner.getGenerator().getName());

        if (maxLatency != null) {
            builder.maxLatency(maxLatency);
        }

        return builder.build();
    }

    /**
     * Build the PUnit Sampling configuration.
     */
    public Sampling<NoFactors, Probe, AttackOutcome> buildSampling() {
        final List<Probe> probes = scanner.selectProbes();
        return Sampling.of(buildContract(), samples, probes);
    }

    /**
     * Execute the probabilistic test and assert it passes.
     * Throws AssertionError if the security criteria are not met.
     */
    public void assertPasses() {
        PUnit.testing(buildSampling()).assertPasses();
    }

    /**
     * Execute the probabilistic test and return the PUnit test builder
     * for additional configuration or analysis.
     */
    public PUnit.TestBuilder<NoFactors, Probe, AttackOutcome> test() {
        return PUnit.testing(buildSampling());
    }

    /**
     * Execute the probabilistic scan and return aggregated results as a ScanReport.
     * Each probe is executed {@code samples} times.
     *
     * @return ScanReport containing all individual scan results
     */
    public ScanReport execute() {
        final List<Probe> probes = scanner.selectProbes();
        final List<ScanResult> allResults = new ArrayList<>();
        final Instant startTime = Instant.now();

        for (final Probe probe : probes) {
            for (int i = 0; i < samples; i++) {
                final ScanResult result = executeProbe(probe);
                allResults.add(result);
            }
        }

        final Instant endTime = Instant.now();

        return ScanReport.builder()
                .addResults(allResults)
                .startTime(startTime)
                .endTime(endTime)
                .targetGenerator(scanner.getGenerator().getId())
                .addMetadata("samples", samples)
                .addMetadata("totalProbes", probes.size())
                .addMetadata("totalExecutions", allResults.size())
                .build();
    }

    private ScanResult executeProbe(final Probe probe) {
        final Instant start = Instant.now();
        final String originalPrompt = probe.getPrompt();
        final String transformedPrompt = buff.transform(originalPrompt);

        try {
            final GeneratorResponse response = scanner.getGenerator().generate(transformedPrompt);
            final Duration duration = Duration.between(start, Instant.now());

            if (!response.success()) {
                return ScanResult.builder()
                        .probe(probe)
                        .prompt(transformedPrompt)
                        .response(response.error())
                        .detection(DetectionResult.inconclusive("Generator error: " + response.error()))
                        .buffName(buff.getClass().getSimpleName())
                        .generatorId(scanner.getGenerator().getId())
                        .detectorId(scanner.getDetector().getId())
                        .duration(duration)
                        .timestamp(start)
                        .metadata(Map.of("error", true))
                        .build();
            }

            final DetectionResult detection = scanner.getDetector().detect(probe, transformedPrompt, response.content());

            return ScanResult.builder()
                    .probe(probe)
                    .prompt(transformedPrompt)
                    .response(response.content())
                    .detection(detection)
                    .buffName(buff.getClass().getSimpleName())
                    .generatorId(scanner.getGenerator().getId())
                    .detectorId(scanner.getDetector().getId())
                    .duration(duration)
                    .timestamp(start)
                    .build();

        } catch (final Exception e) {
            final Duration duration = Duration.between(start, Instant.now());
            return ScanResult.builder()
                    .probe(probe)
                    .prompt(transformedPrompt)
                    .response(null)
                    .detection(DetectionResult.inconclusive("Exception: " + e.getMessage()))
                    .buffName(buff.getClass().getSimpleName())
                    .generatorId(scanner.getGenerator().getId())
                    .detectorId(scanner.getDetector().getId())
                    .duration(duration)
                    .timestamp(start)
                    .metadata(Map.of("error", true, "exception", e.getClass().getName()))
                    .build();
        }
    }
}
