package io.tiberius.guardrail;

import java.util.List;

/**
 * Result of a guardrail check.
 *
 * @param blocked whether the content was blocked
 * @param guardrailId the guardrail that made the decision
 * @param reason explanation for blocking (null if allowed)
 * @param indicators detected patterns or keywords that triggered blocking
 */
public record GuardrailResult(
    boolean blocked,
    String guardrailId,
    String reason,
    List<String> indicators
) {
    /**
     * Content is allowed to pass.
     */
    public static GuardrailResult allow(String guardrailId) {
        return new GuardrailResult(false, guardrailId, null, List.of());
    }

    /**
     * Content is blocked.
     */
    public static GuardrailResult block(String guardrailId, String reason) {
        return new GuardrailResult(true, guardrailId, reason, List.of());
    }

    /**
     * Content is blocked with detected indicators.
     */
    public static GuardrailResult block(String guardrailId, String reason, List<String> indicators) {
        return new GuardrailResult(true, guardrailId, reason, indicators);
    }
}
