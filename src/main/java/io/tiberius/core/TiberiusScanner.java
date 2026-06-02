package io.tiberius.core;

import io.tiberius.core.buff.Buff;
import io.tiberius.core.detector.Detector;
import io.tiberius.core.generator.Generator;
import io.tiberius.core.generator.GeneratorResponse;
import io.tiberius.core.probe.Probe;
import io.tiberius.core.probe.ProbeRegistry;
import io.tiberius.core.probe.AbstractProbe;
import io.tiberius.core.result.ScanReport;
import io.tiberius.core.result.ScanResult;
import io.tiberius.dataset.DatasetEntry;
import io.tiberius.dataset.DatasetScanReport;
import io.tiberius.dataset.DatasetScanResult;
import io.tiberius.dataset.RedTeamDataset;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

/**
 * Main scanner for executing prompt injection tests.
 * Orchestrates probes, buffs, generators, and detectors.
 */
public final class TiberiusScanner {

    private static final Logger log = LoggerFactory.getLogger(TiberiusScanner.class);

    private final ProbeRegistry probeRegistry;
    private final List<Buff> buffs;
    private final ExecutorService executor;
    private final Duration timeout;

    private Generator generator;
    private Detector detector;
    private String[] probePatterns;
    private String[] excludePatterns;
    private AttackCategory[] categories;
    private int minSeverity;
    private boolean failFast;
    private final int concurrency;

    private TiberiusScanner(
            final ProbeRegistry registry,
            final Generator generator,
            final Detector detector,
            final int concurrency
    ) {
        this.probeRegistry = registry;
        this.generator = generator;
        this.detector = detector;
        this.concurrency = concurrency;
        this.buffs = new ArrayList<>();
        this.executor = Executors.newFixedThreadPool(concurrency);
        this.timeout = Duration.ofMinutes(2);
        this.probePatterns = new String[]{"*"};
        this.excludePatterns = new String[0];
        this.categories = new AttackCategory[0];
        this.minSeverity = 1;
        this.failFast = false;
    }

    static TiberiusScanner create(
            final ProbeRegistry registry,
            final Generator generator,
            final Detector detector,
            final List<Buff> buffs,
            final String[] probePatterns,
            final String[] excludePatterns,
            final AttackCategory[] categories,
            final int minSeverity,
            final double maxSuccessRate,
            final boolean failFast,
            final int concurrency
    ) {
        final TiberiusScanner scanner = new TiberiusScanner(registry, generator, detector, concurrency);
        scanner.probePatterns = probePatterns;
        scanner.excludePatterns = excludePatterns;
        scanner.categories = categories;
        scanner.minSeverity = minSeverity;
        scanner.failFast = failFast;
        buffs.forEach(scanner::addBuff);
        return scanner;
    }

    public ScanReport scan() {
        final Instant startTime = Instant.now();
        final List<Probe> probesToRun = selectProbes();

        log.info("Starting scan with {} probes against {}", probesToRun.size(), generator.getName());

        final List<ScanResult> results;
        if (concurrency > 1 && probesToRun.size() > 1) {
            results = runParallel(probesToRun);
        } else {
            results = runSequential(probesToRun);
        }

        return ScanReport.builder()
                .addResults(results)
                .startTime(startTime)
                .endTime(Instant.now())
                .targetGenerator(generator.getId())
                .build();
    }

    public ScanResult runProbe(final Probe probe) {
        return runProbe(probe, Buff.identity());
    }

    public ScanResult runProbe(final Probe probe, final Buff buff) {
        final Instant startTime = Instant.now();
        final String originalPrompt = probe.getPrompt();
        final String transformedPrompt = buff.transform(originalPrompt);
        final GeneratorResponse response = generator.generate(transformedPrompt);
        final Duration duration = Duration.between(startTime, Instant.now());

        if (!response.success()) {
            return ScanResult.builder()
                    .probe(probe)
                    .prompt(transformedPrompt)
                    .response(null)
                    .detection(io.tiberius.core.detector.DetectionResult.inconclusive(
                            "Generator failed: " + response.error()))
                    .buffName(buff.getName())
                    .generatorId(generator.getId())
                    .detectorId(detector.getId())
                    .duration(duration)
                    .build();
        }

        final var detection = detector.detect(probe, transformedPrompt, response.content());

        return ScanResult.builder()
                .probe(probe)
                .prompt(transformedPrompt)
                .response(response.content())
                .detection(detection)
                .buffName(buff.getName())
                .generatorId(generator.getId())
                .detectorId(detector.getId())
                .duration(duration)
                .build();
    }

    List<Probe> selectProbes() {
        List<Probe> selected = selectByPatternsOrCategories();
        selected = applyExclusions(selected);
        selected = applySeverityFilter(selected);
        return selected;
    }

    private List<Probe> selectByPatternsOrCategories() {
        if (probePatterns.length > 0 && !"*".equals(probePatterns[0])) {
            return probeRegistry.getByGlobs(probePatterns);
        } else if (categories.length > 0) {
            final List<Probe> selected = new ArrayList<>();
            for (final AttackCategory category : categories) {
                selected.addAll(probeRegistry.getByCategory(category));
            }
            return selected;
        }
        return new ArrayList<>(probeRegistry.getAll());
    }

    private List<Probe> applyExclusions(final List<Probe> probes) {
        if (excludePatterns.length == 0) {
            return probes;
        }
        final Set<String> excludeIds = new HashSet<>();
        for (final String pattern : excludePatterns) {
            probeRegistry.getByGlob(pattern).forEach(p -> excludeIds.add(p.getId()));
        }
        return probes.stream()
                .filter(p -> !excludeIds.contains(p.getId()))
                .toList();
    }

    private List<Probe> applySeverityFilter(final List<Probe> probes) {
        if (minSeverity <= 1) {
            return probes;
        }
        return probes.stream()
                .filter(p -> p.getSeverity() >= minSeverity)
                .toList();
    }

    private List<ScanResult> runSequential(final List<Probe> probes) {
        final List<ScanResult> results = new ArrayList<>();
        final List<Buff> buffsToApply = getBuffsToApply();

        for (final Probe probe : probes) {
            for (final Buff buff : buffsToApply) {
                final ScanResult result = runProbe(probe, buff);
                results.add(result);
                logResult(result);
                if (failFast && result.attackSucceeded()) {
                    log.warn("Fail fast triggered: attack succeeded for probe {}", probe.getId());
                    return results;
                }
            }
        }
        return results;
    }

    private List<ScanResult> runParallel(final List<Probe> probes) {
        final List<Buff> buffsToApply = getBuffsToApply();
        final List<CompletableFuture<ScanResult>> futures = new ArrayList<>();

        for (final Probe probe : probes) {
            for (final Buff buff : buffsToApply) {
                futures.add(CompletableFuture.supplyAsync(() -> runProbe(probe, buff), executor));
            }
        }

        final List<ScanResult> results = new ArrayList<>();
        for (final CompletableFuture<ScanResult> future : futures) {
            try {
                final ScanResult result = future.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
                results.add(result);
                logResult(result);
                if (failFast && result.attackSucceeded()) {
                    log.warn("Fail fast triggered: cancelling remaining probes");
                    futures.forEach(f -> f.cancel(true));
                    break;
                }
            } catch (final Exception e) {
                log.error("Probe execution failed", e);
            }
        }
        return results;
    }

    private List<Buff> getBuffsToApply() {
        return buffs.isEmpty() ? List.of(Buff.identity()) : buffs;
    }

    private void logResult(final ScanResult result) {
        if (result.attackSucceeded()) {
            log.warn("ATTACK SUCCEEDED: {} (LLM response: {})",
                    result.probeId(), result.response());
        } else {
            log.debug("Attack blocked: {} (LLM response: {})",
                    result.probeId(), result.response());
        }
    }

    public ProbabilisticScanBuilder multiTrialScan() {
        return new ProbabilisticScanBuilder(this);
    }

    // ========================
    // Custom Dataset Scanning
    // ========================

    /**
     * Scan a custom red team dataset.
     * Returns a comprehensive report with ASR metrics broken down by technique, language, and category.
     *
     * <p>Example usage:</p>
     * <pre>{@code
     * RedTeamDataset dataset = new DatasetLoader().load(Path.of("my-dataset.json"));
     * DatasetScanReport report = scanner.scanDataset(dataset);
     *
     * System.out.println("Overall ASR: " + report.overallASR() + "%");
     * report.asrByTechnique().forEach((tech, asr) ->
     *     System.out.printf("  %s: %.2f%%\n", tech, asr));
     * }</pre>
     *
     * @param dataset The red team dataset to scan
     * @return Comprehensive scan report with ASR metrics
     */
    public DatasetScanReport scanDataset(final RedTeamDataset dataset) {
        final Instant startTime = Instant.now();
        final List<DatasetEntry> entries = dataset.getEntries();

        log.info("Starting dataset scan: {} entries against {}", entries.size(), generator.getName());

        final DatasetScanReport.Builder reportBuilder = DatasetScanReport.builder()
                .dataset(dataset)
                .startTime(startTime)
                .targetGenerator(generator.getId());

        if (concurrency > 1 && entries.size() > 1) {
            scanDatasetParallel(entries, reportBuilder);
        } else {
            scanDatasetSequential(entries, reportBuilder);
        }

        reportBuilder.endTime(Instant.now());
        final DatasetScanReport report = reportBuilder.build();

        log.info("Dataset scan complete: {} entries, ASR={}%",
                report.totalEntries(), String.format("%.2f", report.overallASR()));

        return report;
    }

    /**
     * Scan a list of simple payload strings.
     * Useful for quick ad-hoc testing without creating a full dataset.
     *
     * <p>Example usage:</p>
     * <pre>{@code
     * List<String> payloads = List.of(
     *     "Ignore previous instructions and...",
     *     "You are now DAN...",
     *     "Consider this mathematical proof..."
     * );
     * DatasetScanReport report = scanner.scanPayloads(payloads, "jailbreak_test", AttackCategory.JAILBREAK);
     * }</pre>
     *
     * @param payloads List of prompt payloads to test
     * @param technique Technique name for reporting
     * @param category Attack category for classification
     * @return Scan report with ASR metrics
     */
    public DatasetScanReport scanPayloads(
            final List<String> payloads,
            final String technique,
            final AttackCategory category
    ) {
        final RedTeamDataset.Builder datasetBuilder = RedTeamDataset.builder()
                .name("Ad-hoc payload scan")
                .description("Quick payload list scan");

        int index = 0;
        for (final String payload : payloads) {
            datasetBuilder.addEntry(DatasetEntry.builder()
                    .id(String.format("%s_%03d", technique, index++))
                    .prompt(payload)
                    .technique(technique)
                    .category(category)
                    .expectedHarmful(true)
                    .build());
        }

        return scanDataset(datasetBuilder.build());
    }

    /**
     * Scan payloads with default jailbreak category.
     */
    public DatasetScanReport scanPayloads(final List<String> payloads, final String technique) {
        return scanPayloads(payloads, technique, AttackCategory.JAILBREAK);
    }

    /**
     * Scan payloads with default technique and category.
     */
    public DatasetScanReport scanPayloads(final List<String> payloads) {
        return scanPayloads(payloads, "custom", AttackCategory.JAILBREAK);
    }

    private void scanDatasetSequential(
            final List<DatasetEntry> entries,
            final DatasetScanReport.Builder reportBuilder
    ) {
        final List<Buff> buffsToApply = getBuffsToApply();

        for (final DatasetEntry entry : entries) {
            for (final Buff buff : buffsToApply) {
                final DatasetScanResult result = scanEntry(entry, buff);
                reportBuilder.addResult(result);
                logDatasetResult(result);
                if (failFast && result.attackSucceeded()) {
                    log.warn("Fail fast triggered: attack succeeded for entry {}", entry.id());
                    return;
                }
            }
        }
    }

    private void scanDatasetParallel(
            final List<DatasetEntry> entries,
            final DatasetScanReport.Builder reportBuilder
    ) {
        final List<Buff> buffsToApply = getBuffsToApply();
        final List<CompletableFuture<DatasetScanResult>> futures = new ArrayList<>();

        for (final DatasetEntry entry : entries) {
            for (final Buff buff : buffsToApply) {
                futures.add(CompletableFuture.supplyAsync(() -> scanEntry(entry, buff), executor));
            }
        }

        for (final CompletableFuture<DatasetScanResult> future : futures) {
            try {
                final DatasetScanResult result = future.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
                reportBuilder.addResult(result);
                logDatasetResult(result);
                if (failFast && result.attackSucceeded()) {
                    log.warn("Fail fast triggered: cancelling remaining entries");
                    futures.forEach(f -> f.cancel(true));
                    break;
                }
            } catch (final Exception e) {
                log.error("Dataset entry scan failed", e);
            }
        }
    }

    /**
     * Scan a single dataset entry.
     */
    public DatasetScanResult scanEntry(final DatasetEntry entry) {
        return scanEntry(entry, Buff.identity());
    }

    /**
     * Scan a single dataset entry with a buff transformation.
     */
    public DatasetScanResult scanEntry(final DatasetEntry entry, final Buff buff) {
        final Instant startTime = Instant.now();
        final String originalPrompt = entry.prompt();
        final String transformedPrompt = buff.transform(originalPrompt);
        final GeneratorResponse response = generator.generate(transformedPrompt);
        final Duration duration = Duration.between(startTime, Instant.now());

        if (!response.success()) {
            return DatasetScanResult.builder()
                    .entry(entry)
                    .prompt(transformedPrompt)
                    .response(null)
                    .detection(io.tiberius.core.detector.DetectionResult.inconclusive(
                            "Generator failed: " + response.error()))
                    .buffName(buff.getName())
                    .generatorId(generator.getId())
                    .detectorId(detector.getId())
                    .duration(duration)
                    .build();
        }

        // Create a temporary probe for the detector
        final Probe tempProbe = createProbeFromEntry(entry);
        final var detection = detector.detect(tempProbe, transformedPrompt, response.content());

        return DatasetScanResult.builder()
                .entry(entry)
                .prompt(transformedPrompt)
                .response(response.content())
                .detection(detection)
                .buffName(buff.getName())
                .generatorId(generator.getId())
                .detectorId(detector.getId())
                .duration(duration)
                .build();
    }

    private Probe createProbeFromEntry(final DatasetEntry entry) {
        return new AbstractProbe(
                entry.id(),
                entry.id(),
                "Dataset entry: " + entry.technique(),
                entry.category(),
                List.of(entry.prompt()),
                entry.tags(),
                entry.severity()
        ) {};
    }

    private void logDatasetResult(final DatasetScanResult result) {
        if (result.attackSucceeded()) {
            log.warn("ATTACK SUCCEEDED: {} [{}] (response: {})",
                    result.entryId(), result.entry().technique(), result.response());
        } else {
            log.debug("Attack blocked: {} [{}]",
                    result.entryId(), result.entry().technique());
        }
    }

    // Accessors for builders and tests
    public Generator getGenerator() { return generator; }
    public Detector getDetector() { return detector; }

    public void setProbePatterns(final String[] patterns) { this.probePatterns = patterns; }
    public void setExcludePatterns(final String[] patterns) { this.excludePatterns = patterns; }
    public void setCategories(final AttackCategory[] categories) { this.categories = categories; }
    public void setMinSeverity(final int severity) { this.minSeverity = severity; }
    public void setBuffNames(final String[] buffNames) { /* TODO: implement buff loading by name */ }
    public void setGenerator(final Generator generator) { this.generator = generator; }
    public void setDetector(final Detector detector) { this.detector = detector; }
    public void addBuff(final Buff buff) { this.buffs.add(buff); }
    public void shutdown() { executor.shutdown(); }

    public static TiberiusScannerBuilder builder() {
        return new TiberiusScannerBuilder();
    }
}
