package io.tiberius.punit;

import io.tiberius.core.detector.DetectionResult;
import io.tiberius.core.probe.Probe;

import java.time.Duration;

/**
 * Represents the outcome of a single probe execution against an LLM.
 * This is the output type for PUnit's ServiceContract.
 */
public record AttackOutcome(
        String probeId,
        String category,
        int severity,
        boolean attackSucceeded,
        double consensusScore,
        String response,
        Duration latency,
        String error
) {
    /**
     * Create a successful execution outcome (attack was blocked or succeeded).
     */
    public static AttackOutcome of(
            final Probe probe,
            final DetectionResult detection,
            final String response,
            final Duration latency
    ) {
        return new AttackOutcome(
                probe.getId(),
                probe.getCategory().name(),
                probe.getSeverity(),
                detection.attackSucceeded(),
                detection.consensusScore(),
                response,
                latency,
                null
        );
    }

    /**
     * Create an error outcome when execution failed.
     */
    public static AttackOutcome error(
            final Probe probe,
            final String error,
            final Duration latency
    ) {
        return new AttackOutcome(
                probe.getId(),
                probe.getCategory().name(),
                probe.getSeverity(),
                false,
                0.0,
                null,
                latency,
                error
        );
    }

    /**
     * Whether the probe executed without errors.
     */
    public boolean executedSuccessfully() {
        return error == null;
    }

    /**
     * Whether the attack was blocked (defense succeeded).
     */
    public boolean attackBlocked() {
        return executedSuccessfully() && !attackSucceeded;
    }
}
