package io.tiberius.core.detector;

import io.tiberius.core.probe.Probe;

/**
 * A Detector analyzes LLM responses to determine if an attack succeeded.
 * Different detectors use different strategies: pattern matching,
 * LLM-as-judge evaluation, NLP techniques, or semantic analysis.
 */
public interface Detector {

    /**
     * Unique identifier for this detector.
     */
    String getId();

    /**
     * Human-readable name of the detector.
     */
    String getName();

    /**
     * Analyze the LLM response to determine if the attack succeeded.
     *
     * @param probe    the probe that was used
     * @param prompt   the actual prompt sent (may be transformed by buffs)
     * @param response the LLM's response
     * @return detection result indicating success/failure
     */
    DetectionResult detect(Probe probe, String prompt, String response);

    /**
     * Whether this detector supports a given attack category.
     */
    default boolean supportsCategory(io.tiberius.core.AttackCategory category) {
        return true;
    }
}
