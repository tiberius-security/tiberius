package io.tiberius.core.generator;

import java.time.Duration;
import java.util.Map;

/**
 * Response from an LLM generator.
 */
public record GeneratorResponse(
        String content,
        String model,
        Duration latency,
        TokenUsage tokenUsage,
        Map<String, Object> metadata,
        boolean success,
        String error
) {
    public GeneratorResponse {
        metadata = metadata != null ? Map.copyOf(metadata) : Map.of();
    }

    public static GeneratorResponse success(
            final String content,
            final String model,
            final Duration latency
    ) {
        return new GeneratorResponse(content, model, latency, null, Map.of(), true, null);
    }

    public static GeneratorResponse success(
            final String content,
            final String model,
            final Duration latency,
            final TokenUsage usage
    ) {
        return new GeneratorResponse(content, model, latency, usage, Map.of(), true, null);
    }

    public static GeneratorResponse failure(final String error) {
        return new GeneratorResponse(null, null, Duration.ZERO, null, Map.of(), false, error);
    }

    /**
     * Create a blocked response (guardrail triggered).
     */
    public static GeneratorResponse blocked(final String guardrailId, final String reason) {
        return new GeneratorResponse(
                null, null, Duration.ZERO, null,
                Map.of("blockedBy", guardrailId, "blockReason", reason),
                false,
                "Blocked by guardrail: " + guardrailId + " - " + reason
        );
    }

    /**
     * Check if this response was blocked by a guardrail.
     */
    public boolean isBlocked() {
        return metadata.containsKey("blockedBy");
    }

    /**
     * Get the guardrail ID that blocked this request (if any).
     */
    public String blockedBy() {
        return (String) metadata.get("blockedBy");
    }

    /**
     * Token usage information.
     */
    public record TokenUsage(int promptTokens, int completionTokens, int totalTokens) {
        public static TokenUsage of(final int prompt, final int completion) {
            return new TokenUsage(prompt, completion, prompt + completion);
        }
    }
}
