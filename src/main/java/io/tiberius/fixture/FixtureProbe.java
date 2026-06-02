package io.tiberius.fixture;

import io.tiberius.core.AttackCategory;

import java.util.List;

/**
 * JSON-serializable DTO representation of a {@link io.tiberius.core.probe.Probe}.
 */
public record FixtureProbe(
    String id,
    String name,
    String description,
    AttackCategory category,
    List<String> prompts,
    int severity,
    List<String> tags
) {}
