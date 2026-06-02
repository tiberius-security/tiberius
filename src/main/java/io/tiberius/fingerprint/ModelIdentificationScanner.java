package io.tiberius.fingerprint;

import io.tiberius.core.generator.Generator;
import io.tiberius.core.generator.GeneratorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

/**
 * Scanner for identifying which LLM model is behind an API endpoint.
 * Uses behavioral probes and response analysis to fingerprint models.
 */
public final class ModelIdentificationScanner {

    private static final Logger log = LoggerFactory.getLogger(ModelIdentificationScanner.class);

    private final Generator generator;
    private final FingerprintAnalyzer analyzer;
    private final List<FingerprintProbe> probes;
    private final ExecutorService executor;
    private final ScanConfig config;

    private ModelIdentificationScanner(
            final Generator generator,
            final FingerprintAnalyzer analyzer,
            final List<FingerprintProbe> probes,
            final ScanConfig config
    ) {
        this.generator = generator;
        this.analyzer = analyzer;
        this.probes = List.copyOf(probes);
        this.config = config;
        this.executor = Executors.newFixedThreadPool(config.concurrency());
    }

    static ModelIdentificationScanner create(
            final Generator generator,
            final FingerprintAnalyzer analyzer,
            final List<FingerprintProbe> probes,
            final ScanConfig config
    ) {
        return new ModelIdentificationScanner(generator, analyzer, probes, config);
    }

    public ModelIdentificationResult identify() {
        final Instant startTime = Instant.now();
        final ModelIdentificationResult.Builder resultBuilder = ModelIdentificationResult.builder()
                .startTime(startTime);

        log.info("Starting model identification with {} probes", probes.size());

        final List<FingerprintProbe> probesToRun = selectProbes();
        final Map<FingerprintProbe, String> probeResponses = new HashMap<>();
        final Map<String, Double> runningConfidence = new HashMap<>();

        if (config.concurrency() > 1) {
            runParallel(probesToRun, resultBuilder, probeResponses, runningConfidence);
        } else {
            runSequential(probesToRun, resultBuilder, probeResponses, runningConfidence);
        }

        if (config.runBehavioralAnalysis() && !probeResponses.isEmpty()) {
            final Map<String, Double> behaviorScores = analyzer.analyzeBehavioralSignatures(probeResponses);
            for (final Map.Entry<String, Double> entry : behaviorScores.entrySet()) {
                runningConfidence.merge(entry.getKey(), entry.getValue(), Double::sum);
            }
            resultBuilder.addMetadata("behavioralAnalysisRun", true);
        }

        final Duration duration = Duration.between(startTime, Instant.now());
        resultBuilder.duration(duration);
        resultBuilder.addMetadata("totalProbes", probesToRun.size());
        resultBuilder.addMetadata("generatorId", generator.getId());

        final ModelIdentificationResult result = resultBuilder.build();

        log.info("Identification complete in {}ms. Result: {} ({}% confidence)",
                duration.toMillis(), result.identifiedModel(),
                String.format("%.1f", result.overallConfidence() * 100));

        return result;
    }

    public ModelIdentificationResult quickIdentify() {
        final List<FingerprintProbe> quickProbes = FingerprintProbe.quickSet();
        final ModelIdentificationScanner quickScanner = builder()
                .withGenerator(generator)
                .withProbes(quickProbes)
                .withConfig(ScanConfig.quick())
                .build();
        return quickScanner.identify();
    }

    private List<FingerprintProbe> selectProbes() {
        List<FingerprintProbe> selected = new ArrayList<>(probes);
        selected.sort((a, b) -> Double.compare(b.weight(), a.weight()));

        if (config.maxProbes() > 0 && selected.size() > config.maxProbes()) {
            selected = selected.subList(0, config.maxProbes());
        }
        return selected;
    }

    private void runSequential(
            final List<FingerprintProbe> probes,
            final ModelIdentificationResult.Builder resultBuilder,
            final Map<FingerprintProbe, String> probeResponses,
            final Map<String, Double> runningConfidence
    ) {
        for (final FingerprintProbe probe : probes) {
            final ModelIdentificationResult.ProbeResult probeResult = runProbe(probe);
            resultBuilder.addProbeResult(probeResult);

            if (probeResult.isSuccess()) {
                probeResponses.put(probe, probeResult.response());
                updateConfidence(probeResult, runningConfidence);

                if (shouldEarlyStop(runningConfidence)) {
                    break;
                }
            }
        }
    }

    private void runParallel(
            final List<FingerprintProbe> probes,
            final ModelIdentificationResult.Builder resultBuilder,
            final Map<FingerprintProbe, String> probeResponses,
            final Map<String, Double> runningConfidence
    ) {
        final List<FingerprintProbe> priorityProbes = probes.stream()
                .filter(p -> p.weight() > 0.7).toList();
        final List<FingerprintProbe> normalProbes = probes.stream()
                .filter(p -> p.weight() <= 0.7).toList();

        runProbesBatch(priorityProbes, resultBuilder, probeResponses, runningConfidence);

        if (!shouldEarlyStop(runningConfidence)) {
            runProbesBatch(normalProbes, resultBuilder, probeResponses, runningConfidence);
        }
    }

    private void runProbesBatch(
            final List<FingerprintProbe> probes,
            final ModelIdentificationResult.Builder resultBuilder,
            final Map<FingerprintProbe, String> probeResponses,
            final Map<String, Double> runningConfidence
    ) {
        final List<CompletableFuture<ModelIdentificationResult.ProbeResult>> futures = probes.stream()
                .map(probe -> CompletableFuture.supplyAsync(() -> runProbe(probe), executor))
                .toList();

        for (final CompletableFuture<ModelIdentificationResult.ProbeResult> future : futures) {
            try {
                final ModelIdentificationResult.ProbeResult result =
                        future.get(config.probeTimeout().toMillis(), TimeUnit.MILLISECONDS);
                resultBuilder.addProbeResult(result);

                if (result.isSuccess()) {
                    probeResponses.put(result.probe(), result.response());
                    updateConfidence(result, runningConfidence);
                }
            } catch (final Exception e) {
                log.warn("Probe execution failed: {}", e.getMessage());
            }
        }
    }

    private ModelIdentificationResult.ProbeResult runProbe(final FingerprintProbe probe) {
        final Instant start = Instant.now();

        try {
            log.debug("Running probe: {}", probe.name());
            final GeneratorResponse response = generator.generate(probe.prompt());
            final Duration latency = Duration.between(start, Instant.now());

            if (!response.success()) {
                return ModelIdentificationResult.ProbeResult.failure(probe,
                        "Generator error: " + response.error());
            }

            final FingerprintAnalyzer.AnalysisResult analysis = analyzer.analyze(probe, response.content());
            return ModelIdentificationResult.ProbeResult.success(
                    probe, response.content(), analysis.matchesPerModel(),
                    analysis.confidencePerModel(), latency);

        } catch (final Exception e) {
            log.error("Probe {} failed with exception", probe.id(), e);
            return ModelIdentificationResult.ProbeResult.failure(probe, e.getMessage());
        }
    }

    private void updateConfidence(
            final ModelIdentificationResult.ProbeResult result,
            final Map<String, Double> runningConfidence
    ) {
        for (final Map.Entry<String, Double> entry : result.confidenceContribution().entrySet()) {
            runningConfidence.merge(entry.getKey(), entry.getValue(), Double::sum);
        }
    }

    private boolean shouldEarlyStop(final Map<String, Double> runningConfidence) {
        if (!config.earlyStop()) return false;

        return findLeader(runningConfidence)
                .map(leader -> normalizeConfidence(runningConfidence, leader) >= config.earlyStopThreshold())
                .orElse(false);
    }

    private Optional<String> findLeader(final Map<String, Double> scores) {
        return scores.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey);
    }

    private double normalizeConfidence(final Map<String, Double> scores, final String modelId) {
        final double total = scores.values().stream().mapToDouble(Double::doubleValue).sum();
        return total == 0 ? 0 : scores.getOrDefault(modelId, 0.0) / total;
    }

    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (final InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    public static ModelIdentificationScannerBuilder builder() {
        return new ModelIdentificationScannerBuilder();
    }

    public static ModelIdentificationScanner quick(final Generator generator) {
        return builder().withGenerator(generator).withProbes(FingerprintProbe.quickSet())
                .withConfig(ScanConfig.quick()).build();
    }

    public static ModelIdentificationScanner thorough(final Generator generator) {
        return builder().withGenerator(generator).withConfig(ScanConfig.thorough()).build();
    }

    public static ModelIdentificationScanner create(final Generator generator) {
        return builder().withGenerator(generator).build();
    }
}
