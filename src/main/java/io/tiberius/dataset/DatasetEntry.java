package io.tiberius.dataset;

import io.tiberius.core.AttackCategory;

import java.util.List;
import java.util.Map;

/**
 * Represents a single entry in a red team evaluation dataset.
 * Inspired by academic red teaming studies like "Red Teaming GPT-OSS-20B".
 *
 * <p>Each entry contains an adversarial prompt along with metadata for
 * categorization, analysis, and ASR (Attack Success Rate) calculation.</p>
 *
 * @param id Unique identifier for this entry
 * @param prompt The adversarial or evaluation prompt
 * @param category Attack category for this entry
 * @param technique Specific technique used (e.g., "math_proof", "scientific_citation", "iterative_reasoning")
 * @param language Language code (e.g., "en", "de-CH" for Swiss German)
 * @param expectedHarmful Whether the prompt is expected to elicit harmful content (for jailbreaks)
 * @param biasScenario For bias evaluation: the ambiguous scenario being tested
 * @param expectedBias For bias evaluation: the stereotypical assumption being tested
 * @param severity Severity level 1-5
 * @param tags Additional tags for filtering
 * @param metadata Arbitrary additional metadata
 */
public record DatasetEntry(
        String id,
        String prompt,
        AttackCategory category,
        String technique,
        String language,
        boolean expectedHarmful,
        String biasScenario,
        String expectedBias,
        int severity,
        List<String> tags,
        Map<String, Object> metadata
) {
    /**
     * Canonical constructor with validation.
     */
    public DatasetEntry {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("Entry id cannot be null or blank");
        }
        if (prompt == null || prompt.isBlank()) {
            throw new IllegalArgumentException("Entry prompt cannot be null or blank");
        }
        if (category == null) {
            throw new IllegalArgumentException("Entry category cannot be null");
        }
        technique = technique != null ? technique : "unknown";
        language = language != null ? language : "en";
        severity = Math.max(1, Math.min(5, severity));
        tags = tags != null ? List.copyOf(tags) : List.of();
        metadata = metadata != null ? Map.copyOf(metadata) : Map.of();
    }

    /**
     * Check if this is a bias evaluation entry.
     */
    public boolean isBiasEvaluation() {
        return category == AttackCategory.BIAS_EVALUATION || biasScenario != null;
    }

    /**
     * Check if this is a jailbreak/adversarial entry.
     */
    public boolean isAdversarial() {
        return expectedHarmful || category == AttackCategory.JAILBREAK
                || category == AttackCategory.CONTEXTUAL_EMBEDDING
                || category == AttackCategory.PROMPT_INJECTION;
    }

    /**
     * Builder for creating DatasetEntry instances.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder class for DatasetEntry.
     */
    public static class Builder {
        private String id;
        private String prompt;
        private AttackCategory category = AttackCategory.JAILBREAK;
        private String technique;
        private String language = "en";
        private boolean expectedHarmful = true;
        private String biasScenario;
        private String expectedBias;
        private int severity = 3;
        private List<String> tags = List.of();
        private Map<String, Object> metadata = Map.of();

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        public Builder prompt(String prompt) {
            this.prompt = prompt;
            return this;
        }

        public Builder category(AttackCategory category) {
            this.category = category;
            return this;
        }

        public Builder technique(String technique) {
            this.technique = technique;
            return this;
        }

        public Builder language(String language) {
            this.language = language;
            return this;
        }

        public Builder expectedHarmful(boolean expectedHarmful) {
            this.expectedHarmful = expectedHarmful;
            return this;
        }

        public Builder biasScenario(String biasScenario) {
            this.biasScenario = biasScenario;
            return this;
        }

        public Builder expectedBias(String expectedBias) {
            this.expectedBias = expectedBias;
            return this;
        }

        public Builder severity(int severity) {
            this.severity = severity;
            return this;
        }

        public Builder tags(List<String> tags) {
            this.tags = tags;
            return this;
        }

        public Builder tags(String... tags) {
            this.tags = List.of(tags);
            return this;
        }

        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }

        public DatasetEntry build() {
            return new DatasetEntry(
                    id, prompt, category, technique, language,
                    expectedHarmful, biasScenario, expectedBias,
                    severity, tags, metadata
            );
        }
    }
}