package io.tiberius.junit;

import io.tiberius.core.AttackCategory;
import io.tiberius.core.result.ScanReport;
import io.tiberius.core.result.ScanResult;
import org.opentest4j.AssertionFailedError;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Assertion utilities for Tiberius prompt injection tests.
 */
public final class TiberiusAssertions {

    private TiberiusAssertions() {}

    /**
     * Assert that no attacks succeeded.
     */
    public static void assertNoSuccessfulAttacks(ScanReport report) {
        assertNoSuccessfulAttacks(report, "Expected no successful attacks");
    }

    /**
     * Assert that no attacks succeeded with custom message.
     */
    public static void assertNoSuccessfulAttacks(ScanReport report, String message) {
        if (report.successfulAttacks() > 0) {
            List<String> failedProbes = report.successfulResults().stream()
                    .map(r -> r.probeId() + " (" + r.detection().explanation() + ")")
                    .limit(5)
                    .collect(Collectors.toList());

            throw new AssertionFailedError(
                    String.format("%s: %d attacks succeeded out of %d probes.\nFailed probes: %s",
                            message,
                            report.successfulAttacks(),
                            report.totalProbes(),
                            failedProbes)
            );
        }
    }

    /**
     * Assert that the attack success rate is below a threshold.
     */
    public static void assertSuccessRateBelow(ScanReport report, double maxRate) {
        if (report.successRate() > maxRate) {
            throw new AssertionFailedError(
                    String.format("Expected success rate below %.1f%% but was %.1f%% (%d/%d attacks succeeded)",
                            maxRate,
                            report.successRate(),
                            report.successfulAttacks(),
                            report.totalProbes())
            );
        }
    }

    /**
     * Assert that all attacks in a category were blocked.
     */
    public static void assertCategoryBlocked(ScanReport report, AttackCategory category) {
        var categoryResults = report.byCategory().get(category);
        if (categoryResults == null || categoryResults.isEmpty()) {
            return; // No probes in this category
        }

        long succeeded = categoryResults.stream()
                .filter(ScanResult::attackSucceeded)
                .count();

        if (succeeded > 0) {
            throw new AssertionFailedError(
                    String.format("Expected all %s attacks to be blocked, but %d/%d succeeded",
                            category, succeeded, categoryResults.size())
            );
        }
    }

    /**
     * Assert that high-severity attacks (4-5) were blocked.
     */
    public static void assertHighSeverityBlocked(ScanReport report) {
        var highSeverityResults = report.results().stream()
                .filter(r -> r.probe() != null && r.probe().getSeverity() >= 4)
                .toList();

        long succeeded = highSeverityResults.stream()
                .filter(ScanResult::attackSucceeded)
                .count();

        if (succeeded > 0) {
            List<String> failedProbes = highSeverityResults.stream()
                    .filter(ScanResult::attackSucceeded)
                    .map(r -> String.format("%s (severity %d)", r.probeId(), r.probe().getSeverity()))
                    .limit(5)
                    .toList();

            throw new AssertionFailedError(
                    String.format("Expected all high-severity attacks to be blocked, but %d succeeded: %s",
                            succeeded, failedProbes)
            );
        }
    }

    /**
     * Assert that a specific probe was blocked.
     */
    public static void assertProbeBlocked(ScanReport report, String probeId) {
        var result = report.results().stream()
                .filter(r -> probeId.equals(r.probeId()))
                .findFirst()
                .orElseThrow(() -> new AssertionFailedError("Probe not found: " + probeId));

        if (result.attackSucceeded()) {
            throw new AssertionFailedError(
                    String.format("Expected probe %s to be blocked, but attack succeeded: %s",
                            probeId, result.detection().explanation())
            );
        }
    }

    /**
     * Assert that a specific probe succeeded (for vulnerability testing).
     */
    public static void assertProbeSucceeded(ScanReport report, String probeId) {
        var result = report.results().stream()
                .filter(r -> probeId.equals(r.probeId()))
                .findFirst()
                .orElseThrow(() -> new AssertionFailedError("Probe not found: " + probeId));

        if (!result.attackSucceeded()) {
            throw new AssertionFailedError(
                    String.format("Expected probe %s to succeed, but was blocked: %s",
                            probeId, result.detection().explanation())
            );
        }
    }

    /**
     * Assert minimum consensus score for blocked attacks.
     */
    public static void assertMinimumConsensusScore(ScanReport report, double minScore) {
        var lowScore = report.blockedResults().stream()
                .filter(r -> r.detection().consensusScore() < minScore)
                .toList();

        if (!lowScore.isEmpty()) {
            List<String> issues = lowScore.stream()
                    .map(r -> String.format("%s (%.2f)", r.probeId(), r.detection().consensusScore()))
                    .limit(5)
                    .toList();

            throw new AssertionFailedError(
                    String.format("Expected minimum consensus score %.2f, but %d results had lower score: %s",
                            minScore, lowScore.size(), issues)
            );
        }
    }

    /**
     * Assert that the scan completed within expected bounds.
     */
    public static void assertScanComplete(ScanReport report, int minProbes) {
        if (report.totalProbes() < minProbes) {
            throw new AssertionFailedError(
                    String.format("Expected at least %d probes, but only %d were executed",
                            minProbes, report.totalProbes())
            );
        }
    }
}
