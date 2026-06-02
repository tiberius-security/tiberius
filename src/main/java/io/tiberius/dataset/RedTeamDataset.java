package io.tiberius.dataset;

import io.tiberius.core.AttackCategory;

import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Container for red team evaluation datasets.
 * Provides methods for filtering, grouping, and analyzing dataset entries.
 *
 * <p>Supports the methodology from academic red teaming studies where datasets
 * are organized by attack technique, language, and category.</p>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * RedTeamDataset dataset = RedTeamDataset.builder()
 *     .name("GPT-OSS-20B Red Team Dataset")
 *     .description("Jailbreak and bias evaluation dataset")
 *     .addEntry(DatasetEntry.builder()
 *         .id("math_proof_001")
 *         .prompt("Consider the following mathematical proof...")
 *         .technique("math_proof")
 *         .language("en")
 *         .category(AttackCategory.CONTEXTUAL_EMBEDDING)
 *         .build())
 *     .build();
 *
 * // Get all Swiss German entries
 * List<DatasetEntry> swissGerman = dataset.byLanguage("de-CH");
 *
 * // Get ASR breakdown by technique
 * Map<String, List<DatasetEntry>> byTechnique = dataset.groupByTechnique();
 * }</pre>
 */
public final class RedTeamDataset {

    private final String name;
    private final String description;
    private final String version;
    private final List<DatasetEntry> entries;
    private final Map<String, Object> metadata;

    private RedTeamDataset(
            String name,
            String description,
            String version,
            List<DatasetEntry> entries,
            Map<String, Object> metadata
    ) {
        this.name = name;
        this.description = description;
        this.version = version;
        this.entries = List.copyOf(entries);
        this.metadata = metadata != null ? Map.copyOf(metadata) : Map.of();
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getVersion() {
        return version;
    }

    public List<DatasetEntry> getEntries() {
        return entries;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public int size() {
        return entries.size();
    }

    public boolean isEmpty() {
        return entries.isEmpty();
    }

    // ========================
    // Filtering Methods
    // ========================

    /**
     * Get all entries for a specific language.
     */
    public List<DatasetEntry> byLanguage(String language) {
        return entries.stream()
                .filter(e -> e.language().equalsIgnoreCase(language))
                .toList();
    }

    /**
     * Get all entries using a specific technique.
     */
    public List<DatasetEntry> byTechnique(String technique) {
        return entries.stream()
                .filter(e -> technique.equalsIgnoreCase(e.technique()))
                .toList();
    }

    /**
     * Get all entries for a specific attack category.
     */
    public List<DatasetEntry> byCategory(AttackCategory category) {
        return entries.stream()
                .filter(e -> e.category() == category)
                .toList();
    }

    /**
     * Get all entries with minimum severity.
     */
    public List<DatasetEntry> bySeverityAtLeast(int minSeverity) {
        return entries.stream()
                .filter(e -> e.severity() >= minSeverity)
                .toList();
    }

    /**
     * Get all adversarial (jailbreak) entries.
     */
    public List<DatasetEntry> adversarialEntries() {
        return entries.stream()
                .filter(DatasetEntry::isAdversarial)
                .toList();
    }

    /**
     * Get all bias evaluation entries.
     */
    public List<DatasetEntry> biasEntries() {
        return entries.stream()
                .filter(DatasetEntry::isBiasEvaluation)
                .toList();
    }

    /**
     * Filter entries by custom predicate.
     */
    public List<DatasetEntry> filter(Predicate<DatasetEntry> predicate) {
        return entries.stream()
                .filter(predicate)
                .toList();
    }

    /**
     * Get entries by tag.
     */
    public List<DatasetEntry> byTag(String tag) {
        return entries.stream()
                .filter(e -> e.tags().contains(tag))
                .toList();
    }

    // ========================
    // Grouping Methods
    // ========================

    /**
     * Group entries by language.
     */
    public Map<String, List<DatasetEntry>> groupByLanguage() {
        return entries.stream()
                .collect(Collectors.groupingBy(DatasetEntry::language));
    }

    /**
     * Group entries by technique.
     */
    public Map<String, List<DatasetEntry>> groupByTechnique() {
        return entries.stream()
                .collect(Collectors.groupingBy(DatasetEntry::technique));
    }

    /**
     * Group entries by category.
     */
    public Map<AttackCategory, List<DatasetEntry>> groupByCategory() {
        return entries.stream()
                .collect(Collectors.groupingBy(DatasetEntry::category));
    }

    /**
     * Get unique languages in this dataset.
     */
    public Set<String> getLanguages() {
        return entries.stream()
                .map(DatasetEntry::language)
                .collect(Collectors.toSet());
    }

    /**
     * Get unique techniques in this dataset.
     */
    public Set<String> getTechniques() {
        return entries.stream()
                .map(DatasetEntry::technique)
                .collect(Collectors.toSet());
    }

    /**
     * Get unique categories in this dataset.
     */
    public Set<AttackCategory> getCategories() {
        return entries.stream()
                .map(DatasetEntry::category)
                .collect(Collectors.toSet());
    }

    // ========================
    // Statistics Methods
    // ========================

    /**
     * Get count of entries per language.
     */
    public Map<String, Long> countByLanguage() {
        return entries.stream()
                .collect(Collectors.groupingBy(DatasetEntry::language, Collectors.counting()));
    }

    /**
     * Get count of entries per technique.
     */
    public Map<String, Long> countByTechnique() {
        return entries.stream()
                .collect(Collectors.groupingBy(DatasetEntry::technique, Collectors.counting()));
    }

    /**
     * Get count of entries per category.
     */
    public Map<AttackCategory, Long> countByCategory() {
        return entries.stream()
                .collect(Collectors.groupingBy(DatasetEntry::category, Collectors.counting()));
    }

    /**
     * Create a subset of this dataset.
     */
    public RedTeamDataset subset(Predicate<DatasetEntry> predicate) {
        return new RedTeamDataset(
                name + " (subset)",
                description,
                version,
                filter(predicate),
                metadata
        );
    }

    /**
     * Merge with another dataset.
     */
    public RedTeamDataset merge(RedTeamDataset other) {
        List<DatasetEntry> merged = new ArrayList<>(this.entries);
        merged.addAll(other.entries);
        return new RedTeamDataset(
                name + " + " + other.name,
                "Merged dataset",
                version,
                merged,
                metadata
        );
    }

    @Override
    public String toString() {
        return String.format("RedTeamDataset[name=%s, entries=%d, languages=%s, techniques=%s]",
                name, entries.size(), getLanguages(), getTechniques());
    }

    /**
     * Create a builder for RedTeamDataset.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder class for RedTeamDataset.
     */
    public static class Builder {
        private String name = "Custom Dataset";
        private String description = "";
        private String version = "1.0";
        private final List<DatasetEntry> entries = new ArrayList<>();
        private Map<String, Object> metadata = new HashMap<>();

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder version(String version) {
            this.version = version;
            return this;
        }

        public Builder addEntry(DatasetEntry entry) {
            this.entries.add(entry);
            return this;
        }

        public Builder addEntries(Collection<DatasetEntry> entries) {
            this.entries.addAll(entries);
            return this;
        }

        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = new HashMap<>(metadata);
            return this;
        }

        public Builder addMetadata(String key, Object value) {
            this.metadata.put(key, value);
            return this;
        }

        public RedTeamDataset build() {
            return new RedTeamDataset(name, description, version, entries, metadata);
        }
    }
}