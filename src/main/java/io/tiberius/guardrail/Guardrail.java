package io.tiberius.guardrail;

/**
 * Interface for input/output guardrails in LLM-enriched applications.
 *
 * <p>Guardrails inspect content and decide whether to allow or block it.
 * They can be applied to:
 * <ul>
 *   <li><b>Input guardrails</b>: Block malicious prompts before they reach the LLM</li>
 *   <li><b>Output guardrails</b>: Block harmful responses before they reach the user</li>
 * </ul>
 */
public interface Guardrail {

    /**
     * Unique identifier for this guardrail.
     */
    String getId();

    /**
     * Human-readable name.
     */
    String getName();

    /**
     * Check if the content should be blocked.
     *
     * @param content the input prompt or output response to check
     * @return result indicating whether to block and why
     */
    GuardrailResult check(String content);

    /**
     * The type of guardrail (input or output).
     */
    default GuardrailType getType() {
        return GuardrailType.INPUT;
    }

    enum GuardrailType {
        INPUT,
        OUTPUT
    }
}
