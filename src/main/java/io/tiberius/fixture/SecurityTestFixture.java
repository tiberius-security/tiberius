package io.tiberius.fixture;

import java.time.Instant;
import java.util.List;

/**
 * Root DTO for a security test fixture file.
 *
 * <p>Supports two modes:
 * <ul>
 *   <li><b>Normal mode</b>: {@code results} contains individual scan results</li>
 *   <li><b>Statistical mode</b>: {@code probeStatistics} contains aggregated per-probe statistics</li>
 * </ul>
 *
 * @param version fixture format version
 * @param name fixture name identifier
 * @param createdAt when the fixture was first created
 * @param lastUpdatedAt when the fixture was last updated
 * @param generatorId the generator (target LLM) used
 * @param metadata fixture metadata
 * @param statisticalMode whether this fixture uses statistical comparison
 * @param results individual scan results (normal mode)
 * @param probeStatistics aggregated probe statistics (statistical mode)
 */
public record SecurityTestFixture(
    String version,
    String name,
    Instant createdAt,
    Instant lastUpdatedAt,
    String generatorId,
    FixtureMetadata metadata,
    boolean statisticalMode,
    List<FixtureScanResult> results,
    List<FixtureProbeStatistics> probeStatistics
) {
    /**
     * Check if this fixture uses statistical mode.
     */
    public boolean isStatisticalMode() {
        return statisticalMode;
    }

    /**
     * Check if this fixture has individual results (normal mode).
     */
    public boolean hasResults() {
        return results != null && !results.isEmpty();
    }

    /**
     * Check if this fixture has probe statistics (statistical mode).
     */
    public boolean hasProbeStatistics() {
        return probeStatistics != null && !probeStatistics.isEmpty();
    }
}
