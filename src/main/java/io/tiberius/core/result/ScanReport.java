package io.tiberius.core.result;

import io.tiberius.core.AttackCategory;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Aggregated report of multiple scan results.
 */
public record ScanReport(
        /* All individual scan results */
        List<ScanResult> results,

        /* When the scan started */
        Instant startTime,

        /* When the scan completed */
        Instant endTime,

        /* Target generator ID */
        String targetGenerator,

        /* Report metadata */
        Map<String, Object> metadata
) {
    public ScanReport {
        results = results != null ? List.copyOf(results) : List.of();
        metadata = metadata != null ? Map.copyOf(metadata) : Map.of();
    }

    /**
     * Total number of probes tested.
     */
    public int totalProbes() {
        return results.size();
    }

    /**
     * Number of successful attacks.
     */
    public int successfulAttacks() {
        return (int) results.stream().filter(ScanResult::attackSucceeded).count();
    }

    /**
     * Number of blocked attacks.
     */
    public int blockedAttacks() {
        return totalProbes() - successfulAttacks();
    }

    /**
     * Success rate as a percentage.
     */
    public double successRate() {
        return totalProbes() == 0 ? 0.0 : (successfulAttacks() * 100.0) / totalProbes();
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

    /**
     * Get results grouped by attack category.
     */
    public Map<AttackCategory, List<ScanResult>> byCategory() {
        return results.stream()
                .filter(r -> r.category() != null)
                .collect(Collectors.groupingBy(ScanResult::category));
    }

    /**
     * Get successful attacks only.
     */
    public List<ScanResult> successfulResults() {
        return results.stream()
                .filter(ScanResult::attackSucceeded)
                .toList();
    }

    /**
     * Get blocked attacks only.
     */
    public List<ScanResult> blockedResults() {
        return results.stream()
                .filter(r -> !r.attackSucceeded())
                .toList();
    }

    /**
     * Get results by severity level.
     */
    public Map<Integer, List<ScanResult>> bySeverity() {
        return results.stream()
                .filter(r -> r.probe() != null)
                .collect(Collectors.groupingBy(r -> r.probe().getSeverity()));
    }

    /**
     * Get results grouped by probe ID.
     * Each probe may have multiple results (one per prompt variant and buff combination).
     */
    public Map<String, List<ScanResult>> byProbe() {
        return results.stream()
                .filter(r -> r.probe() != null)
                .collect(Collectors.groupingBy(r -> r.probe().getId()));
    }

    /**
     * Compute success rate per probe.
     * Returns a map of probe ID to success rate percentage.
     * Each probe's success rate is computed across all its prompt variants.
     */
    public Map<String, Double> successRateByProbe() {
        return byProbe().entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> {
                            List<ScanResult> probeResults = e.getValue();
                            long successes = probeResults.stream()
                                    .filter(ScanResult::attackSucceeded)
                                    .count();
                            return probeResults.isEmpty() ? 0.0
                                    : (successes * 100.0) / probeResults.size();
                        }
                ));
    }

    /**
     * Compute the mean success rate across all probes.
     * This averages the per-probe success rates, giving each probe equal weight
     * regardless of how many prompt variants it has.
     */
    public double meanSuccessRateByProbe() {
        Map<String, Double> perProbeRates = successRateByProbe();
        if (perProbeRates.isEmpty()) {
            return 0.0;
        }
        return perProbeRates.values().stream()
                .mapToDouble(Double::doubleValue)
                .average()
                .orElse(0.0);
    }

    /**
     * Number of unique probes tested.
     */
    public int uniqueProbeCount() {
        return (int) results.stream()
                .filter(r -> r.probe() != null)
                .map(r -> r.probe().getId())
                .distinct()
                .count();
    }

    /**
     * Summary statistics for each probe.
     */
    public Map<String, ProbeSummary> probeSummaries() {
        return byProbe().entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> {
                            List<ScanResult> probeResults = e.getValue();
                            int total = probeResults.size();
                            int successful = (int) probeResults.stream()
                                    .filter(ScanResult::attackSucceeded)
                                    .count();
                            String probeName = probeResults.isEmpty() ? e.getKey()
                                    : probeResults.get(0).probe().getName();
                            return new ProbeSummary(e.getKey(), probeName, total, successful);
                        }
                ));
    }

    /**
     * Summary for a single probe across all its prompt variants.
     */
    public record ProbeSummary(String probeId, String probeName, int totalPrompts, int successful) {
        public int blocked() {
            return totalPrompts - successful;
        }

        public double successRate() {
            return totalPrompts == 0 ? 0.0 : (successful * 100.0) / totalPrompts;
        }
    }

    /**
     * Summary statistics for each category.
     */
    public Map<AttackCategory, CategorySummary> categorySummaries() {
        return byCategory().entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> new CategorySummary(
                                e.getKey(),
                                e.getValue().size(),
                                (int) e.getValue().stream().filter(ScanResult::attackSucceeded).count()
                        )
                ));
    }

    /**
     * Summary for a single category.
     */
    public record CategorySummary(AttackCategory category, int total, int successful) {
        public int blocked() {
            return total - successful;
        }

        public double successRate() {
            return total == 0 ? 0.0 : (successful * 100.0) / total;
        }
    }

    /**
     * Create a builder for ScanReport.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for ScanReport.
     */
    public static class Builder {
        private final List<ScanResult> results = new ArrayList<>();
        private Instant startTime;
        private Instant endTime;
        private String targetGenerator;
        private Map<String, Object> metadata = new HashMap<>();

        public Builder addResult(ScanResult result) {
            results.add(result);
            return this;
        }

        public Builder addResults(Collection<ScanResult> results) {
            this.results.addAll(results);
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

        public ScanReport build() {
            return new ScanReport(results, startTime, endTime, targetGenerator, metadata);
        }
    }
}
