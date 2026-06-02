package io.tiberius.fixture;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * JSON-serializable DTO representation of a {@link io.tiberius.core.result.ScanResult}.
 */
public record FixtureScanResult(
    FixtureProbe probe,
    String prompt,
    String response,
    FixtureDetectionResult detection,
    String buffName,
    String generatorId,
    String detectorId,
    Duration duration,
    Instant timestamp,
    Map<String, Object> metadata
) {}
