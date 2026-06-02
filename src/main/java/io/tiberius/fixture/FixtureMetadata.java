package io.tiberius.fixture;

import java.util.Map;

/**
 * Metadata about a test fixture.
 */
public record FixtureMetadata(
    String tiberiusVersion,
    String javaVersion,
    String description,
    Map<String, Object> custom
) {}
