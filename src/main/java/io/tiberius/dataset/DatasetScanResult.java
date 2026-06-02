package io.tiberius.dataset;

import io.tiberius.core.detector.DetectionResult;
import io.tiberius.core.result.ScanResult;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * Result of scanning a single dataset entry.
 * Pairs a DatasetEntry with the LLM response and detection outcome.
 *
 * @param entry The dataset entry that was scanned
 * @param prompt The actual prompt sent (may be transformed by buffs)
 * @param response The LLM's response
 * @param detection Detection result indicating if the attack succeeded
 * @param buffName Name of the buff applied (if any)
 * @param generatorId ID of the generator (LLM) used
 * @param detectorId ID of the detector used
 * @param duration Time taken for this scan
 * @param timestamp When the scan was executed
 * @param metadata Additional metadata about this scan
 */
public record DatasetScanResult(
        DatasetEntry entry,
        String prompt,
        String response,
        DetectionResult detection,
        String buffName,
        String generatorId,
        String detectorId,
        Duration duration,
        Instant timestamp,
        Map<String, Object> metadata
) {
    public DatasetScanResult {
        metadata = metadata != null ? Map.copyOf(metadata) : Map.of();
        timestamp = timestamp != null ? timestamp : Instant.now();
    }

    /**
     * Check if the attack succeeded.
     */
    public boolean attackSucceeded() {
        return detection != null && detection.attackSucceeded();
    }

    /**
     * Check if detection was inconclusive.
     */
    public boolean isInconclusive() {
        return detection != null && detection.inconclusive();
    }

    /**
     * Get the entry ID.
     */
    public String entryId() {
        return entry != null ? entry.id() : null;
    }

    /**
     * Create from a core ScanResult and DatasetEntry.
     */
    public static DatasetScanResult from(DatasetEntry entry, ScanResult scanResult) {
        return new DatasetScanResult(
                entry,
                scanResult.prompt(),
                scanResult.response(),
                scanResult.detection(),
                scanResult.buffName(),
                scanResult.generatorId(),
                scanResult.detectorId(),
                scanResult.duration(),
                scanResult.timestamp(),
                scanResult.metadata()
        );
    }

    /**
     * Create a builder.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for DatasetScanResult.
     */
    public static class Builder {
        private DatasetEntry entry;
        private String prompt;
        private String response;
        private DetectionResult detection;
        private String buffName = "identity";
        private String generatorId;
        private String detectorId;
        private Duration duration = Duration.ZERO;
        private Instant timestamp = Instant.now();
        private Map<String, Object> metadata = Map.of();

        public Builder entry(DatasetEntry entry) {
            this.entry = entry;
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

        public DatasetScanResult build() {
            return new DatasetScanResult(
                    entry, prompt, response, detection, buffName,
                    generatorId, detectorId, duration, timestamp, metadata
            );
        }
    }
}