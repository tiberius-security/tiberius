package io.tiberius.core.probe;

import io.tiberius.core.AttackCategory;

import java.util.List;
import java.util.Map;

/**
 * A Probe represents an adversarial input designed to test LLM security.
 * Probes contain the attack payload and metadata about the attack type.
 */
public interface Probe {

    /**
     * Unique identifier for this probe.
     */
    String getId();

    /**
     * Human-readable name of the probe.
     */
    String getName();

    /**
     * Description of what this probe tests.
     */
    String getDescription();

    /**
     * The attack category this probe belongs to.
     */
    AttackCategory getCategory();

    /**
     * Get the adversarial prompts to send to the LLM.
     * May return multiple variants of the attack.
     */
    List<String> getPrompts();

    /**
     * Get the primary adversarial prompt.
     */
    default String getPrompt() {
        List<String> prompts = getPrompts();
        return prompts.isEmpty() ? "" : prompts.get(0);
    }

    /**
     * Tags for filtering and categorization.
     */
    default List<String> getTags() {
        return List.of();
    }

    /**
     * Additional metadata about the probe.
     */
    default Map<String, Object> getMetadata() {
        return Map.of();
    }

    /**
     * The expected detector to use with this probe.
     */
    default String getRecommendedDetector() {
        return "default";
    }

    /**
     * Severity level from 1 (low) to 5 (critical).
     */
    default int getSeverity() {
        return 3;
    }
}
