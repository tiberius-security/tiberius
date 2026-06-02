package io.tiberius.dataset;

import io.tiberius.core.AttackCategory;
import io.tiberius.core.result.ScanResult;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Comprehensive report for red team dataset scan results.
 * Provides ASR (Attack Success Rate) metrics broken down by technique, language, and category.
 *
 * <p>Inspired by academic red teaming methodology from papers like
 * "Red Teaming GPT-OSS-20B: Evaluating Jailbreak Susceptibility and Bias Across English and Swiss German".</p>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * DatasetScanReport report = scanner.scanDataset(dataset);
 *
 * // Overall ASR
 * System.out.println("Overall ASR: " + report.overallASR() + "%");
 *
 * // ASR by technique
 * report.asrByTechnique().forEach((technique, asr) ->
 *     System.out.printf("  %s: %.2f%%\n", technique, asr));
 *
 * // ASR by language
 * report.asrByLanguage().forEach((lang, asr) ->
 *     System.out.printf("  %s: %.2f%%\n", lang, asr));
 *
 * // Bias statistics
 * System.out.println("Bias rate: " + report.biasRate() + "%");
 * }</pre>
 */
public record DatasetScanReport(
        /* The dataset that was scanned */
        RedTeamDataset dataset,

        /* Mapping from entry ID to scan result */
        Map<String, DatasetScanResult> results,

        /* When the scan started */
        Instant startTime,

        /* When the scan completed */
        Instant endTime,

        /* Target generator ID */
        String targetGenerator,

        /* Report metadata */
        Map<String, Object> metadata
) {
    public DatasetScanReport {
        results = results != null ? Map.copyOf(results) : Map.of();
        metadata = metadata != null ? Map.copyOf(metadata) : Map.of();
    }

    // ========================
    // Basic Statistics
    // ========================

    /**
     * Total number of entries scanned.
     */
    public int totalEntries() {
        return results.size();
    }

    /**
     * Number of successful attacks.
     */
    public int successfulAttacks() {
        return (int) results.values().stream()
                .filter(r -> r.attackSucceeded())
                .count();
    }

    /**
     * Number of blocked attacks.
     */
    public int blockedAttacks() {
        return totalEntries() - successfulAttacks();
    }

    /**
     * Total scan duration.
     */
    public Duration totalDuration() {
        if (startTime == null || endTime == null) {
            return Duration.ZERO;
        }
        return Duration.between(startTime, endTime);
    }

    // ========================
    // ASR (Attack Success Rate) Metrics
    // ========================

    /**
     * Overall Attack Success Rate as percentage.
     */
    public double overallASR() {
        return totalEntries() == 0 ? 0.0 : (successfulAttacks() * 100.0) / totalEntries();
    }

    /**
     * ASR broken down by technique.
     */
    public Map<String, Double> asrByTechnique() {
        return computeASRByGroup(DatasetEntry::technique);
    }

    /**
     * ASR broken down by language.
     */
    public Map<String, Double> asrByLanguage() {
        return computeASRByGroup(DatasetEntry::language);
    }

    /**
     * ASR broken down by attack category.
     */
    public Map<AttackCategory, Double> asrByCategory() {
        Map<AttackCategory, List<DatasetScanResult>> grouped = results.values().stream()
                .collect(Collectors.groupingBy(r -> r.entry().category()));

        Map<AttackCategory, Double> asrMap = new EnumMap<>(AttackCategory.class);
        for (var entry : grouped.entrySet()) {
            List<DatasetScanResult> groupResults = entry.getValue();
            long successes = groupResults.stream().filter(DatasetScanResult::attackSucceeded).count();
            double asr = (successes * 100.0) / groupResults.size();
            asrMap.put(entry.getKey(), asr);
        }
        return asrMap;
    }

    /**
     * ASR broken down by severity level.
     */
    public Map<Integer, Double> asrBySeverity() {
        Map<Integer, List<DatasetScanResult>> grouped = results.values().stream()
                .collect(Collectors.groupingBy(r -> r.entry().severity()));

        Map<Integer, Double> asrMap = new TreeMap<>();
        for (var entry : grouped.entrySet()) {
            List<DatasetScanResult> groupResults = entry.getValue();
            long successes = groupResults.stream().filter(DatasetScanResult::attackSucceeded).count();
            double asr = (successes * 100.0) / groupResults.size();
            asrMap.put(entry.getKey(), asr);
        }
        return asrMap;
    }

    private <K> Map<K, Double> computeASRByGroup(java.util.function.Function<DatasetEntry, K> classifier) {
        Map<K, List<DatasetScanResult>> grouped = results.values().stream()
                .collect(Collectors.groupingBy(r -> classifier.apply(r.entry())));

        Map<K, Double> asrMap = new LinkedHashMap<>();
        for (var entry : grouped.entrySet()) {
            List<DatasetScanResult> groupResults = entry.getValue();
            long successes = groupResults.stream().filter(DatasetScanResult::attackSucceeded).count();
            double asr = (successes * 100.0) / groupResults.size();
            asrMap.put(entry.getKey(), asr);
        }
        return asrMap;
    }

    // ========================
    // Bias Evaluation Metrics
    // ========================

    /**
     * Get results for bias evaluation entries only.
     */
    public List<DatasetScanResult> biasResults() {
        return results.values().stream()
                .filter(r -> r.entry().isBiasEvaluation())
                .toList();
    }

    /**
     * Number of bias evaluation entries.
     */
    public int totalBiasEntries() {
        return biasResults().size();
    }

    /**
     * Number of entries where model showed stereotypical bias.
     * (Measured by attackSucceeded for bias evaluation entries)
     */
    public int biasedResponses() {
        return (int) biasResults().stream()
                .filter(DatasetScanResult::attackSucceeded)
                .count();
    }

    /**
     * Bias rate as percentage (similar to the paper's 35.78% figure).
     */
    public double biasRate() {
        int total = totalBiasEntries();
        return total == 0 ? 0.0 : (biasedResponses() * 100.0) / total;
    }

    // ========================
    // Adversarial Evaluation Metrics
    // ========================

    /**
     * Get results for adversarial (jailbreak) entries only.
     */
    public List<DatasetScanResult> adversarialResults() {
        return results.values().stream()
                .filter(r -> r.entry().isAdversarial())
                .toList();
    }

    /**
     * Number of adversarial entries.
     */
    public int totalAdversarialEntries() {
        return adversarialResults().size();
    }

    /**
     * Adversarial ASR (jailbreak success rate).
     */
    public double adversarialASR() {
        List<DatasetScanResult> adversarial = adversarialResults();
        if (adversarial.isEmpty()) return 0.0;
        long successes = adversarial.stream().filter(DatasetScanResult::attackSucceeded).count();
        return (successes * 100.0) / adversarial.size();
    }

    // ========================
    // Detailed Statistics
    // ========================

    /**
     * Get detailed statistics per technique.
     */
    public Map<String, TechniqueStatistics> techniqueStatistics() {
        Map<String, List<DatasetScanResult>> grouped = results.values().stream()
                .collect(Collectors.groupingBy(r -> r.entry().technique()));

        Map<String, TechniqueStatistics> stats = new LinkedHashMap<>();
        for (var entry : grouped.entrySet()) {
            stats.put(entry.getKey(), TechniqueStatistics.from(entry.getKey(), entry.getValue()));
        }
        return stats;
    }

    /**
     * Get detailed statistics per language.
     */
    public Map<String, LanguageStatistics> languageStatistics() {
        Map<String, List<DatasetScanResult>> grouped = results.values().stream()
                .collect(Collectors.groupingBy(r -> r.entry().language()));

        Map<String, LanguageStatistics> stats = new LinkedHashMap<>();
        for (var entry : grouped.entrySet()) {
            stats.put(entry.getKey(), LanguageStatistics.from(entry.getKey(), entry.getValue()));
        }
        return stats;
    }

    /**
     * Get successful attack results.
     */
    public List<DatasetScanResult> successfulResults() {
        return results.values().stream()
                .filter(DatasetScanResult::attackSucceeded)
                .toList();
    }

    /**
     * Get blocked attack results.
     */
    public List<DatasetScanResult> blockedResults() {
        return results.values().stream()
                .filter(r -> !r.attackSucceeded())
                .toList();
    }

    // ========================
    // Report Generation
    // ========================

    /**
     * Generate a summary string similar to academic paper reporting.
     */
    public String toSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Red Team Dataset Scan Report ===\n");
        sb.append(String.format("Dataset: %s\n", dataset.getName()));
        sb.append(String.format("Target: %s\n", targetGenerator));
        sb.append(String.format("Duration: %s\n", formatDuration(totalDuration())));
        sb.append("\n");

        sb.append("--- Overall Results ---\n");
        sb.append(String.format("Total entries: %d\n", totalEntries()));
        sb.append(String.format("Successful attacks: %d\n", successfulAttacks()));
        sb.append(String.format("Overall ASR: %.2f%%\n", overallASR()));
        sb.append("\n");

        if (totalAdversarialEntries() > 0) {
            sb.append("--- Adversarial (Jailbreak) Results ---\n");
            sb.append(String.format("Adversarial entries: %d\n", totalAdversarialEntries()));
            sb.append(String.format("Adversarial ASR: %.2f%%\n", adversarialASR()));
            sb.append("\n");
        }

        if (totalBiasEntries() > 0) {
            sb.append("--- Bias Evaluation Results ---\n");
            sb.append(String.format("Bias entries: %d\n", totalBiasEntries()));
            sb.append(String.format("Biased responses: %d\n", biasedResponses()));
            sb.append(String.format("Bias rate: %.2f%%\n", biasRate()));
            sb.append("\n");
        }

        sb.append("--- ASR by Technique ---\n");
        asrByTechnique().forEach((technique, asr) ->
                sb.append(String.format("  %s: %.2f%%\n", technique, asr)));
        sb.append("\n");

        sb.append("--- ASR by Language ---\n");
        asrByLanguage().forEach((lang, asr) ->
                sb.append(String.format("  %s: %.2f%%\n", lang, asr)));

        return sb.toString();
    }

    private String formatDuration(Duration duration) {
        long seconds = duration.getSeconds();
        if (seconds < 60) {
            return String.format("%ds", seconds);
        } else if (seconds < 3600) {
            return String.format("%dm %ds", seconds / 60, seconds % 60);
        } else {
            return String.format("%dh %dm %ds", seconds / 3600, (seconds % 3600) / 60, seconds % 60);
        }
    }

    /**
     * Create a builder for DatasetScanReport.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Statistics for a specific technique.
     */
    public record TechniqueStatistics(
            String technique,
            int total,
            int successful,
            double asr
    ) {
        public int blocked() {
            return total - successful;
        }

        public static TechniqueStatistics from(String technique, List<DatasetScanResult> results) {
            int total = results.size();
            int successful = (int) results.stream().filter(DatasetScanResult::attackSucceeded).count();
            double asr = total == 0 ? 0.0 : (successful * 100.0) / total;
            return new TechniqueStatistics(technique, total, successful, asr);
        }
    }

    /**
     * Statistics for a specific language.
     */
    public record LanguageStatistics(
            String language,
            int total,
            int successful,
            double asr,
            int biasEntries,
            int biasedResponses,
            double biasRate
    ) {
        public int blocked() {
            return total - successful;
        }

        public static LanguageStatistics from(String language, List<DatasetScanResult> results) {
            int total = results.size();
            int successful = (int) results.stream().filter(DatasetScanResult::attackSucceeded).count();
            double asr = total == 0 ? 0.0 : (successful * 100.0) / total;

            List<DatasetScanResult> biasResults = results.stream()
                    .filter(r -> r.entry().isBiasEvaluation())
                    .toList();
            int biasEntries = biasResults.size();
            int biasedResponses = (int) biasResults.stream()
                    .filter(DatasetScanResult::attackSucceeded)
                    .count();
            double biasRate = biasEntries == 0 ? 0.0 : (biasedResponses * 100.0) / biasEntries;

            return new LanguageStatistics(language, total, successful, asr, biasEntries, biasedResponses, biasRate);
        }
    }

    /**
     * Builder class for DatasetScanReport.
     */
    public static class Builder {
        private RedTeamDataset dataset;
        private final Map<String, DatasetScanResult> results = new LinkedHashMap<>();
        private Instant startTime;
        private Instant endTime;
        private String targetGenerator;
        private Map<String, Object> metadata = new HashMap<>();

        public Builder dataset(RedTeamDataset dataset) {
            this.dataset = dataset;
            return this;
        }

        public Builder addResult(String entryId, DatasetScanResult result) {
            this.results.put(entryId, result);
            return this;
        }

        public Builder addResult(DatasetScanResult result) {
            this.results.put(result.entry().id(), result);
            return this;
        }

        public Builder startTime(Instant startTime) {
            this.startTime = startTime;
            return this;
        }

        public Builder endTime(Instant endTime) {
            this.endTime = endTime;
            return this;
        }

        public Builder targetGenerator(String targetGenerator) {
            this.targetGenerator = targetGenerator;
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

        public DatasetScanReport build() {
            return new DatasetScanReport(dataset, results, startTime, endTime, targetGenerator, metadata);
        }
    }
}