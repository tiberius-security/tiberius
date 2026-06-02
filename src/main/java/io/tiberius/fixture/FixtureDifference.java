package io.tiberius.fixture;

/**
 * Represents a single difference between a fixture and actual scan results.
 */
public record FixtureDifference(
    String probeId,
    String field,
    Object expected,
    Object actual
) {}
