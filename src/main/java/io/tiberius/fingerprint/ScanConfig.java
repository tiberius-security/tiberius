package io.tiberius.fingerprint;

import java.time.Duration;

/**
 * Configuration for model identification scanning.
 * Extracted from ModelIdentificationScanner to keep classes under 100 lines.
 */
public record ScanConfig(
        int concurrency,
        Duration probeTimeout,
        boolean earlyStop,
        double earlyStopThreshold,
        boolean runBehavioralAnalysis,
        int maxProbes
) {
    /**
     * Default configuration for standard scanning.
     */
    public static ScanConfig defaults() {
        return new ScanConfig(5, Duration.ofSeconds(30), true, 0.85, true, 0);
    }

    /**
     * Quick configuration for fast identification with reduced accuracy.
     */
    public static ScanConfig quick() {
        return new ScanConfig(3, Duration.ofSeconds(15), true, 0.75, false, 5);
    }

    /**
     * Thorough configuration for highest accuracy.
     */
    public static ScanConfig thorough() {
        return new ScanConfig(10, Duration.ofSeconds(60), false, 0.95, true, 0);
    }
}
