package io.tiberius.fixture;

import io.tiberius.core.detector.DetectionResult;
import io.tiberius.core.probe.Probe;
import io.tiberius.core.result.ScanReport;
import io.tiberius.core.result.ScanResult;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Converts between domain objects and fixture DTOs.
 */
public final class FixtureConverter {

    private static final String TIBERIUS_VERSION = "1.0.0-SNAPSHOT";
    private static final String JAVA_VERSION = System.getProperty("java.version");

    private FixtureConverter() {}

    /**
     * Convert ScanReport to a normal (non-statistical) fixture.
     */
    public static SecurityTestFixture toFixture(
            final ScanReport report,
            final String name,
            final String version,
            final String description
    ) {
        final Instant now = Instant.now();
        final List<FixtureScanResult> results = report.results().stream()
                .map(FixtureConverter::toFixture)
                .toList();

        final FixtureMetadata metadata = new FixtureMetadata(
                TIBERIUS_VERSION,
                JAVA_VERSION,
                description,
                report.metadata()
        );

        return new SecurityTestFixture(
                version, name, now, now, report.targetGenerator(), metadata,
                false, results, List.of()
        );
    }

    /**
     * Convert ScanReport to a statistical fixture with aggregated probe statistics.
     */
    public static SecurityTestFixture toStatisticalFixture(
            final ScanReport report,
            final String name,
            final String version,
            final String description
    ) {
        final Instant now = Instant.now();
        final List<FixtureProbeStatistics> statistics = aggregateByProbe(report);

        final FixtureMetadata metadata = new FixtureMetadata(
                TIBERIUS_VERSION,
                JAVA_VERSION,
                description,
                report.metadata()
        );

        return new SecurityTestFixture(
                version, name, now, now, report.targetGenerator(), metadata,
                true, List.of(), statistics
        );
    }

    /**
     * Aggregate scan results by probe ID into statistics.
     */
    public static List<FixtureProbeStatistics> aggregateByProbe(final ScanReport report) {
        final Map<String, List<ScanResult>> byProbe = new LinkedHashMap<>();

        for (final ScanResult result : report.results()) {
            final String probeId = result.probeId();
            byProbe.computeIfAbsent(probeId, k -> new ArrayList<>()).add(result);
        }

        final List<FixtureProbeStatistics> statistics = new ArrayList<>();
        for (final Map.Entry<String, List<ScanResult>> entry : byProbe.entrySet()) {
            statistics.add(computeStatistics(entry.getKey(), entry.getValue()));
        }
        return statistics;
    }

    private static FixtureProbeStatistics computeStatistics(final String probeId, final List<ScanResult> results) {
        int successCount = 0;
        int blockedCount = 0;
        int errorCount = 0;
        double totalConsensusScore = 0;

        String probeName = probeId;
        io.tiberius.core.AttackCategory category = null;

        for (final ScanResult result : results) {
            if (result.probe() != null) {
                probeName = result.probe().getName();
                category = result.probe().getCategory();
            }

            if (result.detection() == null) {
                errorCount++;
            } else if (result.attackSucceeded()) {
                successCount++;
                totalConsensusScore += result.detection().consensusScore();
            } else {
                blockedCount++;
                totalConsensusScore += result.detection().consensusScore();
            }
        }

        final int validResults = successCount + blockedCount;
        final double blockRate = validResults > 0 ? (double) blockedCount / validResults : 0.0;
        final double avgConsensusScore = validResults > 0 ? totalConsensusScore / validResults : 0.0;

        return new FixtureProbeStatistics(
                probeId,
                probeName,
                category,
                results.size(),
                successCount,
                blockedCount,
                errorCount,
                blockRate,
                avgConsensusScore
        );
    }

    public static FixtureScanResult toFixture(final ScanResult result) {
        return new FixtureScanResult(
                result.probe() != null ? toFixture(result.probe()) : null,
                result.prompt(),
                result.response(),
                result.detection() != null ? toFixture(result.detection()) : null,
                result.buffName(),
                result.generatorId(),
                result.detectorId(),
                result.duration(),
                result.timestamp(),
                result.metadata()
        );
    }

    public static FixtureProbe toFixture(final Probe probe) {
        return new FixtureProbe(
                probe.getId(),
                probe.getName(),
                probe.getDescription(),
                probe.getCategory(),
                probe.getPrompts(),
                probe.getSeverity(),
                probe.getTags()
        );
    }

    public static FixtureDetectionResult toFixture(final DetectionResult detection) {
        return new FixtureDetectionResult(
                detection.attackSucceeded(),
                detection.consensusScore(),
                detection.explanation(),
                detection.indicators()
        );
    }

    /**
     * Update an existing normal fixture with new results.
     */
    public static SecurityTestFixture updateFixture(final SecurityTestFixture existing, final ScanReport report) {
        final List<FixtureScanResult> results = report.results().stream()
                .map(FixtureConverter::toFixture)
                .toList();

        final FixtureMetadata metadata = new FixtureMetadata(
                TIBERIUS_VERSION,
                JAVA_VERSION,
                existing.metadata() != null ? existing.metadata().description() : "",
                report.metadata()
        );

        return new SecurityTestFixture(
                existing.version(),
                existing.name(),
                existing.createdAt(),
                Instant.now(),
                report.targetGenerator(),
                metadata,
                false,
                results,
                List.of()
        );
    }

    /**
     * Update an existing statistical fixture with new statistics.
     */
    public static SecurityTestFixture updateStatisticalFixture(final SecurityTestFixture existing, final ScanReport report) {
        final List<FixtureProbeStatistics> statistics = aggregateByProbe(report);

        final FixtureMetadata metadata = new FixtureMetadata(
                TIBERIUS_VERSION,
                JAVA_VERSION,
                existing.metadata() != null ? existing.metadata().description() : "",
                report.metadata()
        );

        return new SecurityTestFixture(
                existing.version(),
                existing.name(),
                existing.createdAt(),
                Instant.now(),
                report.targetGenerator(),
                metadata,
                true,
                List.of(),
                statistics
        );
    }
}
