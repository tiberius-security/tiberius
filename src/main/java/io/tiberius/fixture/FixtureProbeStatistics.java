package io.tiberius.fixture;

import io.tiberius.core.AttackCategory;

/**
 * Aggregated statistics for a single probe across multiple samples.
 * Used in statistical mode for multi-trial scans.
 *
 * @param probeId the probe identifier
 * @param probeName human-readable probe name
 * @param category the attack category
 * @param samples number of samples executed
 * @param successCount number of successful attacks
 * @param blockedCount number of blocked attacks
 * @param errorCount number of errors/inconclusive results
 * @param blockRate proportion of attacks blocked (0.0 to 1.0)
 * @param avgConsensusScore average consensus score across samples
 */
public record FixtureProbeStatistics(
    String probeId,
    String probeName,
    AttackCategory category,
    int samples,
    int successCount,
    int blockedCount,
    int errorCount,
    double blockRate,
    double avgConsensusScore
) {
    /**
     * Check if actual statistics match expected within tolerance.
     *
     * @param actual the actual statistics from a scan
     * @param tolerance acceptable deviation (e.g., 0.1 for 10%)
     * @return true if block rates match within tolerance
     */
    public boolean matchesWithinTolerance(FixtureProbeStatistics actual, double tolerance) {
        return Math.abs(this.blockRate - actual.blockRate) <= tolerance;
    }
}
