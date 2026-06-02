package io.tiberius.fixture;

import java.util.List;

/**
 * JSON-serializable DTO representation of a {@link io.tiberius.core.detector.DetectionResult}.
 */
public record FixtureDetectionResult(
    boolean attackSucceeded,
    double consensusScore,
    String explanation,
    List<String> indicators
) {}
