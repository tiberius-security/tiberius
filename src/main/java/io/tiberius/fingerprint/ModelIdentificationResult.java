package io.tiberius.fingerprint;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Result of a model identification scan.
 * Contains confidence scores for each candidate model and supporting evidence.
 */
public record ModelIdentificationResult(
        Map<String, Double> confidenceScores,

        List<ProbeResult> probeResults,

        String identifiedProvider,

        String identifiedModel,

        double overallConfidence,

        Duration duration,

        Instant timestamp,

        Map<String, Object> metadata
) {
    public ModelIdentificationResult {
        confidenceScores = confidenceScores != null ? Map.copyOf(confidenceScores) : Map.of();
        probeResults = probeResults != null ? List.copyOf(probeResults) : List.of();
        metadata = metadata != null ? Map.copyOf(metadata) : Map.of();
    }

    /**
     * Result of a single fingerprint probe.
     */
    public record ProbeResult(
            FingerprintProbe probe,

            String response,

            Map<String, List<String>> matchesPerModel,

            Map<String, Double> confidenceContribution,

            Duration latency,

            String error
    ) {
        public ProbeResult {
            matchesPerModel = matchesPerModel != null ? Map.copyOf(matchesPerModel) : Map.of();
            confidenceContribution = confidenceContribution != null ? Map.copyOf(confidenceContribution) : Map.of();
        }

        /**
         * Create a successful probe result.
         */
        public static ProbeResult success(FingerprintProbe probe, String response,
                                          Map<String, List<String>> matches,
                                          Map<String, Double> confidence, Duration latency) {
            return new ProbeResult(probe, response, matches, confidence, latency, null);
        }

        /**
         * Create a failed probe result.
         */
        public static ProbeResult failure(FingerprintProbe probe, String error) {
            return new ProbeResult(probe, null, Map.of(), Map.of(), Duration.ZERO, error);
        }

        /**
         * Check if the probe was successful.
         */
        public boolean isSuccess() {
            return error == null;
        }

        /**
         * Get the best matching model for this probe.
         */
        public Optional<String> bestMatch() {
            return confidenceContribution.entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .map(Map.Entry::getKey);
        }
    }

    /**
     * Get the top N most likely models.
     */
    public List<ModelCandidate> topCandidates(int n) {
        return confidenceScores.entrySet().stream()
                .sorted(Map.Entry.<String, Double>comparingByValue().reversed())
                .limit(n)
                .map(e -> {
                    ModelFingerprint fp = ModelFingerprint.byId(e.getKey());
                    return new ModelCandidate(
                            e.getKey(),
                            fp != null ? fp.displayName() : e.getKey(),
                            fp != null ? fp.provider() : "Unknown",
                            e.getValue(),
                            getEvidenceForModel(e.getKey())
                    );
                })
                .toList();
    }

    /**
     * A candidate model with confidence score.
     */
    public record ModelCandidate(
            String id,
            String displayName,
            String provider,
            double confidence,
            List<String> evidence
    ) {}

    /**
     * Get evidence supporting identification of a specific model.
     */
    public List<String> getEvidenceForModel(String modelId) {
        List<String> evidence = new ArrayList<>();
        for (ProbeResult result : probeResults) {
            if (result.isSuccess() && result.matchesPerModel().containsKey(modelId)) {
                List<String> matches = result.matchesPerModel().get(modelId);
                if (!matches.isEmpty()) {
                    evidence.add(String.format("[%s] Matched: %s",
                            result.probe().name(),
                            String.join(", ", matches)));
                }
            }
        }
        return evidence;
    }

    /**
     * Check if identification is confident (> threshold).
     */
    public boolean isConfident(double threshold) {
        return overallConfidence >= threshold;
    }

    /**
     * Check if identification is confident with default threshold (0.7).
     */
    public boolean isConfident() {
        return isConfident(0.7);
    }

    /**
     * Get confidence for a specific model.
     */
    public double getConfidenceFor(String modelId) {
        return confidenceScores.getOrDefault(modelId, 0.0);
    }

    /**
     * Get successful probe count.
     */
    public int successfulProbes() {
        return (int) probeResults.stream().filter(ProbeResult::isSuccess).count();
    }

    /**
     * Get failed probe count.
     */
    public int failedProbes() {
        return (int) probeResults.stream().filter(r -> !r.isSuccess()).count();
    }

    /**
     * Generate a human-readable summary.
     */
    public String summary() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Model Identification Result ===\n\n");

        if (identifiedModel != null && overallConfidence > 0.5) {
            sb.append(String.format("Identified: %s (%s)\n", identifiedModel, identifiedProvider));
            sb.append(String.format("Confidence: %.1f%%\n\n", overallConfidence * 100));
        } else {
            sb.append("Unable to confidently identify model.\n\n");
        }

        sb.append("Top Candidates:\n");
        for (ModelCandidate candidate : topCandidates(5)) {
            sb.append(String.format("  %s (%s): %.1f%%\n",
                    candidate.displayName(), candidate.provider(), candidate.confidence() * 100));
        }

        sb.append(String.format("\nProbes: %d successful, %d failed\n",
                successfulProbes(), failedProbes()));
        sb.append(String.format("Duration: %dms\n", duration.toMillis()));

        return sb.toString();
    }

    /**
     * Generate detailed evidence report.
     */
    public String detailedReport() {
        StringBuilder sb = new StringBuilder();
        sb.append(summary());
        sb.append("\n=== Evidence ===\n\n");

        for (ModelCandidate candidate : topCandidates(3)) {
            sb.append(String.format("--- %s ---\n", candidate.displayName()));
            for (String evidence : candidate.evidence()) {
                sb.append("  • ").append(evidence).append("\n");
            }
            sb.append("\n");
        }

        sb.append("=== Probe Details ===\n\n");
        for (ProbeResult result : probeResults) {
            sb.append(String.format("[%s] %s\n",
                    result.isSuccess() ? "✓" : "✗",
                    result.probe().name()));
            if (result.isSuccess()) {
                sb.append(String.format("  Response preview: %.100s...\n",
                        result.response().replaceAll("\\s+", " ")));
                result.bestMatch().ifPresent(best ->
                        sb.append(String.format("  Best match: %s\n", best)));
            } else {
                sb.append(String.format("  Error: %s\n", result.error()));
            }
            sb.append("\n");
        }

        return sb.toString();
    }

    /**
     * Builder for ModelIdentificationResult.
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private final Map<String, Double> confidenceScores = new HashMap<>();
        private final List<ProbeResult> probeResults = new ArrayList<>();
        private Instant startTime;
        private Duration duration = Duration.ZERO;
        private final Map<String, Object> metadata = new HashMap<>();

        public Builder addProbeResult(ProbeResult result) {
            probeResults.add(result);
            // Update confidence scores based on probe result
            for (Map.Entry<String, Double> entry : result.confidenceContribution().entrySet()) {
                confidenceScores.merge(entry.getKey(), entry.getValue(), Double::sum);
            }
            return this;
        }

        public Builder startTime(Instant startTime) {
            this.startTime = startTime;
            return this;
        }

        public Builder duration(Duration duration) {
            this.duration = duration;
            return this;
        }

        public Builder addMetadata(String key, Object value) {
            metadata.put(key, value);
            return this;
        }

        public ModelIdentificationResult build() {
            // Normalize confidence scores to 0-1 range
            double maxScore = confidenceScores.values().stream()
                    .mapToDouble(Double::doubleValue)
                    .max()
                    .orElse(1.0);

            Map<String, Double> normalizedScores = new HashMap<>();
            if (maxScore > 0) {
                for (Map.Entry<String, Double> entry : confidenceScores.entrySet()) {
                    normalizedScores.put(entry.getKey(),
                            Math.min(1.0, entry.getValue() / maxScore));
                }
            }

            // Find best match
            String bestModelId = normalizedScores.entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .map(Map.Entry::getKey)
                    .orElse(null);

            ModelFingerprint bestModel = bestModelId != null ?
                    ModelFingerprint.byId(bestModelId) : null;

            double overallConfidence = bestModelId != null ?
                    normalizedScores.getOrDefault(bestModelId, 0.0) : 0.0;

            return new ModelIdentificationResult(
                    normalizedScores,
                    probeResults,
                    bestModel != null ? bestModel.provider() : "Unknown",
                    bestModel != null ? bestModel.displayName() : bestModelId,
                    overallConfidence,
                    duration,
                    Instant.now(),
                    metadata
            );
        }
    }
}
