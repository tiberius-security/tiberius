package io.tiberius.fixture;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.tiberius.core.result.ScanReport;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Manages reading and writing of fixture files.
 */
public final class TestFixtureGenerator {

    private final ObjectMapper objectMapper;

    public TestFixtureGenerator() {
        this.objectMapper = createObjectMapper();
    }

    private static ObjectMapper createObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return mapper;
    }

    public void write(SecurityTestFixture fixture, Path path) throws IOException {
        Files.createDirectories(path.getParent());
        objectMapper.writeValue(path.toFile(), fixture);
    }

    public SecurityTestFixture read(Path path) throws IOException {
        return objectMapper.readValue(path.toFile(), SecurityTestFixture.class);
    }

    public boolean exists(Path path) {
        return Files.exists(path);
    }

    /**
     * Compare fixture with scan report (normal mode).
     */
    public FixtureComparisonResult compare(SecurityTestFixture fixture, ScanReport report) {
        List<FixtureDifference> differences = new ArrayList<>();

        List<FixtureScanResult> expectedResults = fixture.results();
        List<FixtureScanResult> actualResults = report.results().stream()
                .map(FixtureConverter::toFixture)
                .toList();

        if (expectedResults.size() != actualResults.size()) {
            differences.add(new FixtureDifference("fixture", "resultCount", expectedResults.size(), actualResults.size()));
        }

        for (int i = 0; i < Math.min(expectedResults.size(), actualResults.size()); i++) {
            FixtureScanResult expected = expectedResults.get(i);
            FixtureScanResult actual = actualResults.get(i);
            String probeId = expected.probe() != null ? expected.probe().id() : "unknown-" + i;
            compareResult(expected, actual, probeId, differences);
        }

        return FixtureComparisonResult.withDifferences(differences);
    }

    /**
     * Compare fixture with scan report using statistical comparison.
     *
     * @param fixture the expected fixture with probe statistics
     * @param report the actual scan report
     * @param tolerance acceptable deviation for block rates (e.g., 0.1 for 10%)
     * @return comparison result with any differences found
     */
    public FixtureComparisonResult compareStatistical(
            SecurityTestFixture fixture,
            ScanReport report,
            double tolerance
    ) {
        List<FixtureDifference> differences = new ArrayList<>();

        // Get expected statistics from fixture
        List<FixtureProbeStatistics> expectedStats = fixture.probeStatistics();
        if (expectedStats == null || expectedStats.isEmpty()) {
            differences.add(new FixtureDifference("fixture", "probeStatistics", "expected statistics", "none found"));
            return FixtureComparisonResult.withDifferences(differences);
        }

        // Compute actual statistics from report
        List<FixtureProbeStatistics> actualStats = FixtureConverter.aggregateByProbe(report);

        // Create lookup map for actual statistics
        Map<String, FixtureProbeStatistics> actualByProbeId = actualStats.stream()
                .collect(Collectors.toMap(FixtureProbeStatistics::probeId, Function.identity()));

        // Compare each expected probe
        for (FixtureProbeStatistics expected : expectedStats) {
            FixtureProbeStatistics actual = actualByProbeId.get(expected.probeId());

            if (actual == null) {
                differences.add(new FixtureDifference(
                        expected.probeId(), "presence", "expected", "missing"));
                continue;
            }

            // Compare block rates within tolerance
            double blockRateDiff = Math.abs(expected.blockRate() - actual.blockRate());
            if (blockRateDiff > tolerance) {
                differences.add(new FixtureDifference(
                        expected.probeId(),
                        "blockRate",
                        String.format("%.2f (±%.2f)", expected.blockRate(), tolerance),
                        String.format("%.2f (diff: %.2f)", actual.blockRate(), blockRateDiff)
                ));
            }

            // Check sample count (informational, not a failure)
            if (expected.samples() != actual.samples()) {
                differences.add(new FixtureDifference(
                        expected.probeId(),
                        "samples (info)",
                        expected.samples(),
                        actual.samples()
                ));
            }
        }

        // Check for unexpected probes in actual results
        for (FixtureProbeStatistics actual : actualStats) {
            boolean found = expectedStats.stream()
                    .anyMatch(e -> e.probeId().equals(actual.probeId()));
            if (!found) {
                differences.add(new FixtureDifference(
                        actual.probeId(), "presence", "not expected", "found"));
            }
        }

        return FixtureComparisonResult.withDifferences(differences);
    }

    private void compareResult(FixtureScanResult expected, FixtureScanResult actual, String probeId, List<FixtureDifference> differences) {
        if (expected.detection() != null && actual.detection() != null) {
            if (expected.detection().attackSucceeded() != actual.detection().attackSucceeded()) {
                differences.add(new FixtureDifference(probeId, "detection.attackSucceeded",
                        expected.detection().attackSucceeded(), actual.detection().attackSucceeded()));
            }
            if (Math.abs(expected.detection().consensusScore() - actual.detection().consensusScore()) > 0.01) {
                differences.add(new FixtureDifference(probeId, "detection.consensusScore",
                        expected.detection().consensusScore(), actual.detection().consensusScore()));
            }
        }

        if (!Objects.equals(expected.generatorId(), actual.generatorId())) {
            differences.add(new FixtureDifference(probeId, "generatorId", expected.generatorId(), actual.generatorId()));
        }

        if (!Objects.equals(expected.detectorId(), actual.detectorId())) {
            differences.add(new FixtureDifference(probeId, "detectorId", expected.detectorId(), actual.detectorId()));
        }
    }
}
