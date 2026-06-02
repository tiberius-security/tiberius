package io.tiberius.guardrail;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Report of guardrail validation against a fixture of known attacks.
 *
 * @param fixtureSource the fixture file used as attack source
 * @param totalAttacks total number of attacks replayed
 * @param blockedCount number of attacks blocked by guardrails
 * @param bypassedCount number of attacks that bypassed guardrails
 * @param errorCount number of attacks that resulted in errors
 * @param blockRate ratio of blocked to total attacks (0.0 to 1.0)
 * @param details per-attack validation details
 * @param duration total validation duration
 * @param timestamp when validation was performed
 */
public record GuardrailReport(
    String fixtureSource,
    int totalAttacks,
    int blockedCount,
    int bypassedCount,
    int errorCount,
    double blockRate,
    List<AttackValidation> details,
    Duration duration,
    Instant timestamp
) {
    /**
     * Check if all attacks were blocked.
     */
    public boolean allBlocked() {
        return bypassedCount == 0 && errorCount == 0;
    }

    /**
     * Check if block rate meets the threshold.
     */
    public boolean meetsThreshold(double minBlockRate) {
        return blockRate >= minBlockRate;
    }

    /**
     * Get attacks that bypassed the guardrails.
     */
    public List<AttackValidation> bypasses() {
        return details.stream()
                .filter(d -> d.outcome() == AttackOutcome.BYPASSED)
                .toList();
    }

    /**
     * Detail of a single attack validation.
     *
     * @param probeId the probe that generated the attack
     * @param prompt the attack prompt
     * @param outcome whether blocked, bypassed, or error
     * @param blockedBy guardrail that blocked (if any)
     * @param response LLM response (if bypassed)
     */
    public record AttackValidation(
        String probeId,
        String prompt,
        AttackOutcome outcome,
        String blockedBy,
        String response
    ) {
        public static AttackValidation blocked(String probeId, String prompt, String guardrailId) {
            return new AttackValidation(probeId, prompt, AttackOutcome.BLOCKED, guardrailId, null);
        }

        public static AttackValidation bypassed(String probeId, String prompt, String response) {
            return new AttackValidation(probeId, prompt, AttackOutcome.BYPASSED, null, response);
        }

        public static AttackValidation error(String probeId, String prompt, String errorMessage) {
            return new AttackValidation(probeId, prompt, AttackOutcome.ERROR, null, errorMessage);
        }
    }

    /**
     * Outcome of validating a single attack against guardrails.
     */
    public enum AttackOutcome {
        BLOCKED,    // Guardrail blocked the attack
        BYPASSED,   // Attack bypassed guardrails
        ERROR       // Error during validation
    }

    /**
     * Builder for GuardrailReport.
     */
    public static Builder builder(String fixtureSource) {
        return new Builder(fixtureSource);
    }

    public static final class Builder {
        private final String fixtureSource;
        private final List<AttackValidation> details = new java.util.ArrayList<>();
        private Instant startTime;

        private Builder(String fixtureSource) {
            this.fixtureSource = fixtureSource;
            this.startTime = Instant.now();
        }

        public Builder addBlocked(String probeId, String prompt, String guardrailId) {
            details.add(AttackValidation.blocked(probeId, prompt, guardrailId));
            return this;
        }

        public Builder addBypassed(String probeId, String prompt, String response) {
            details.add(AttackValidation.bypassed(probeId, prompt, response));
            return this;
        }

        public Builder addError(String probeId, String prompt, String error) {
            details.add(AttackValidation.error(probeId, prompt, error));
            return this;
        }

        public GuardrailReport build() {
            int blocked = (int) details.stream().filter(d -> d.outcome() == AttackOutcome.BLOCKED).count();
            int bypassed = (int) details.stream().filter(d -> d.outcome() == AttackOutcome.BYPASSED).count();
            int errors = (int) details.stream().filter(d -> d.outcome() == AttackOutcome.ERROR).count();
            int total = details.size();
            double blockRate = total > 0 ? (double) blocked / total : 0.0;

            return new GuardrailReport(
                    fixtureSource,
                    total,
                    blocked,
                    bypassed,
                    errors,
                    blockRate,
                    List.copyOf(details),
                    Duration.between(startTime, Instant.now()),
                    Instant.now()
            );
        }
    }
}
