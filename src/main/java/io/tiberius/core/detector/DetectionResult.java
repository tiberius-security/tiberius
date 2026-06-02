package io.tiberius.core.detector;

import java.util.List;
import java.util.Map;

/**
 * Result of a detector's analysis of an LLM response.
 */
public record DetectionResult(
        boolean attackSucceeded,
        double consensusScore,
        String explanation,
        List<String> indicators,
        Map<String, Object> metadata
) {
    public DetectionResult {
        indicators = indicators != null ? List.copyOf(indicators) : List.of();
        metadata = metadata != null ? Map.copyOf(metadata) : Map.of();
    }

    public static DetectionResult attackSucceeded(
            final double consensusScore,
            final String explanation
    ) {
        return new DetectionResult(true, consensusScore, explanation, List.of(), Map.of());
    }

    public static DetectionResult attackSucceeded(
            final double consensusScore,
            final String explanation,
            final List<String> indicators
    ) {
        return new DetectionResult(true, consensusScore, explanation, indicators, Map.of());
    }

    public static DetectionResult attackBlocked(
            final double consensusScore,
            final String explanation
    ) {
        return new DetectionResult(false, consensusScore, explanation, List.of(), Map.of());
    }

    public static DetectionResult attackBlocked(
            final double consensusScore,
            final String explanation,
            final List<String> indicators
    ) {
        return new DetectionResult(false, consensusScore, explanation, indicators, Map.of());
    }

    public static DetectionResult inconclusive(final String explanation) {
        return new DetectionResult(false, 0.5, explanation, List.of(), Map.of());
    }

    public boolean inconclusive() {
        return false;
    }
}
