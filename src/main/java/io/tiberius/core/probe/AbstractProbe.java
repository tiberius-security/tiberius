package io.tiberius.core.probe;

import io.tiberius.core.AttackCategory;

import java.util.List;

/**
 * Base implementation for probes with common functionality.
 */
public abstract class AbstractProbe implements Probe {

    private final String id;
    private final String name;
    private final String description;
    private final AttackCategory category;
    private final List<String> prompts;
    private final List<String> tags;
    private final int severity;

    protected AbstractProbe(
            final String id,
            final String name,
            final String description,
            final AttackCategory category,
            final List<String> prompts,
            final List<String> tags,
            final int severity
    ) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.category = category;
        this.prompts = List.copyOf(prompts);
        this.tags = tags != null ? List.copyOf(tags) : List.of();
        this.severity = severity;
    }

    protected AbstractProbe(
            final String id,
            final String name,
            final String description,
            final AttackCategory category,
            final String prompt
    ) {
        this(id, name, description, category, List.of(prompt), List.of(), 3);
    }

    @Override
    public final String getId() {
        return id;
    }

    @Override
    public final String getName() {
        return name;
    }

    @Override
    public final String getDescription() {
        return description;
    }

    @Override
    public final AttackCategory getCategory() {
        return category;
    }

    @Override
    public final List<String> getPrompts() {
        return prompts;
    }

    @Override
    public final List<String> getTags() {
        return tags;
    }

    @Override
    public int getSeverity() {
        return severity;
    }

    @Override
    public final String toString() {
        return String.format("Probe[%s: %s]", id, name);
    }
}
