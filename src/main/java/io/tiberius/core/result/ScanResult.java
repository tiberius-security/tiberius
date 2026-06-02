package io.tiberius.core.result;

import io.tiberius.core.AttackCategory;
import io.tiberius.core.detector.DetectionResult;
import io.tiberius.core.probe.Probe;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Result of a single probe scan against an LLM.
 */
public record ScanResult(
        /* The probe that was used */
        Probe probe,

        /* The actual prompt sent (after any buff transformations) */
        String prompt,

        /* The LLM's response */
        String response,

        /* Detection result from the detector */
        DetectionResult detection,

        /* Name of the buff applied (if any) */
        String buffName,

        /* Generator used */
        String generatorId,

        /* Detector used */
        String detectorId,

        /* Time taken for the scan */
        Duration duration,

        /* When the scan was performed */
        Instant timestamp,

        /* Additional scan metadata */
        Map<String, Object> metadata
) {
    public ScanResult {
        metadata = metadata != null ? Map.copyOf(metadata) : Map.of();
        timestamp = timestamp != null ? timestamp : Instant.now();
    }

    /**
     * Whether the attack succeeded.
     */
    public boolean attackSucceeded() {
        return detection != null && detection.attackSucceeded();
    }

    /**
     * Get the probe ID.
     */
    public String probeId() {
        return probe != null ? probe.getId() : "unknown";
    }

    /**
     * Get the attack category.
     */
    public AttackCategory category() {
        return probe != null ? probe.getCategory() : null;
    }

    /**
     * Create a builder for ScanResult.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for ScanResult.
     */
    public static class Builder {
        private Probe probe;
        private String prompt;
        private String response;
        private DetectionResult detection;
        private String buffName;
        private String generatorId;
        private String detectorId;
        private Duration duration;
        private Instant timestamp;
        private Map<String, Object> metadata = Map.of();

        public Builder probe(Probe probe) {
            this.probe = probe;
            return this;
        }

        public Builder prompt(String prompt) {
            this.prompt = prompt;
            return this;
        }

        public Builder response(String response) {
            this.response = response;
            return this;
        }

        public Builder detection(DetectionResult detection) {
            this.detection = detection;
            return this;
        }

        public Builder buffName(String buffName) {
            this.buffName = buffName;
            return this;
        }

        public Builder generatorId(String generatorId) {
            this.generatorId = generatorId;
            return this;
        }

        public Builder detectorId(String detectorId) {
            this.detectorId = detectorId;
            return this;
        }

        public Builder duration(Duration duration) {
            this.duration = duration;
            return this;
        }

        public Builder timestamp(Instant timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }

        public ScanResult build() {
            return new ScanResult(probe, prompt, response, detection, buffName,
                    generatorId, detectorId, duration, timestamp, metadata);
        }
    }
}
