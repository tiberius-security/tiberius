package io.tiberius.fixture;

import java.util.List;

/**
 * Result of comparing a fixture with actual scan results.
 */
public record FixtureComparisonResult(
    boolean matches,
    List<FixtureDifference> differences
) {
    public static FixtureComparisonResult matching() {
        return new FixtureComparisonResult(true, List.of());
    }

    public static FixtureComparisonResult withDifferences(List<FixtureDifference> differences) {
        return new FixtureComparisonResult(differences.isEmpty(), differences);
    }
}
