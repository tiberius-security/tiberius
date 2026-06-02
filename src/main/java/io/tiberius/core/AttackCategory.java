package io.tiberius.core;

/**
 * Categories of LLM prompt injection attacks supported by Tiberius.
 * Based on the Augustus attack taxonomy.
 */
public enum AttackCategory {

    /** Jailbreak attacks: DAN, AIM, AntiGPT, persona manipulation */
    JAILBREAK("Jailbreak attacks attempting to bypass safety training"),

    /** Encoding-based attacks: Base64, ROT13, Morse, hex encoding */
    ENCODING("Encoding-based evasion attacks"),

    /** Direct prompt injection attacks */
    PROMPT_INJECTION("Direct prompt injection attacks"),

    /** Data extraction: API keys, PII, training data */
    DATA_EXTRACTION("Attacks attempting to extract sensitive data"),

    /** Multi-turn attacks: Crescendo, GOAT, Hydra */
    MULTI_TURN("Multi-turn escalation attacks"),

    /** Format exploits: Markdown, YAML, JSON injection */
    FORMAT_EXPLOIT("Format-based injection attacks"),

    /** Context manipulation: RAG poisoning, overflow */
    CONTEXT_MANIPULATION("Context window manipulation attacks"),

    /** Adversarial examples: GCG, AutoDAN, PAIR */
    ADVERSARIAL("Adversarial suffix and token attacks"),

    /** Safety benchmark probes */
    SAFETY_BENCHMARK("Safety benchmark evaluation probes"),

    /** Evasion techniques: homoglyphs, zero-width chars */
    EVASION("Evasion and obfuscation techniques"),

    /** Bias evaluation: stereotypical assumptions, ambiguous scenarios */
    BIAS_EVALUATION("Bias and fairness evaluation probes"),

    /** Contextual embedding: math proofs, scientific citations, iterative reasoning */
    CONTEXTUAL_EMBEDDING("Contextual manipulation through academic/formal framing");

    private final String description;

    AttackCategory(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
