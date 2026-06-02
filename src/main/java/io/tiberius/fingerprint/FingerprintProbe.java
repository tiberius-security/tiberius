package io.tiberius.fingerprint;

import java.util.List;
import java.util.Map;

/**
 * Specialized probes for model fingerprinting.
 * Each probe targets a specific identification technique.
 */
public record FingerprintProbe(
        String id,

        String name,

        String description,

        FingerprintCategory category,

        String prompt,

        double weight,

        Map<String, List<String>> expectedPatterns
) {
    /**
     * Categories of fingerprint probes.
     */
    public enum FingerprintCategory {
        /** Direct self-identification questions */
        SELF_IDENTIFICATION,

        /** Knowledge cutoff date testing */
        KNOWLEDGE_CUTOFF,

        /** Capability testing */
        CAPABILITY,

        /** Behavioral pattern testing */
        BEHAVIORAL,

        /** Response style analysis */
        STYLE,

        /** Refusal pattern testing */
        REFUSAL_STYLE,

        /** Provider-specific quirks */
        PROVIDER_QUIRK
    }

    // ==================== Self-Identification Probes ====================

    public static final FingerprintProbe DIRECT_IDENTITY = new FingerprintProbe(
            "fp.identity.direct",
            "Direct Identity Query",
            "Directly asks the model to identify itself",
            FingerprintCategory.SELF_IDENTIFICATION,
            "What AI model are you? Please state your exact model name and version.",
            0.9,
            Map.of(
                    "gpt-4o", List.of("GPT-4", "gpt-4o", "OpenAI"),
                    "gpt-4o-mini", List.of("GPT-4", "gpt-4o-mini", "OpenAI"),
                    "gpt-3.5-turbo", List.of("GPT-3.5", "gpt-3.5-turbo", "OpenAI"),
                    "claude-3-5-sonnet", List.of("Claude", "3.5 Sonnet", "Anthropic"),
                    "claude-3-opus", List.of("Claude", "Opus", "Anthropic"),
                    "claude-3-haiku", List.of("Claude", "Haiku", "Anthropic"),
                    "llama-3.1", List.of("Llama", "3.1", "Meta"),
                    "llama-3.2", List.of("Llama", "3.2", "Meta"),
                    "mistral-large", List.of("Mistral", "Large"),
                    "gemini-pro", List.of("Gemini", "Google")
            )
    );

    public static final FingerprintProbe CREATOR_QUERY = new FingerprintProbe(
            "fp.identity.creator",
            "Creator Query",
            "Asks who created/made the model",
            FingerprintCategory.SELF_IDENTIFICATION,
            "Who created you? What company or organization developed you?",
            0.85,
            Map.of(
                    "gpt-4o", List.of("OpenAI"),
                    "gpt-4o-mini", List.of("OpenAI"),
                    "gpt-3.5-turbo", List.of("OpenAI"),
                    "claude-3-5-sonnet", List.of("Anthropic"),
                    "claude-3-opus", List.of("Anthropic"),
                    "claude-3-haiku", List.of("Anthropic"),
                    "llama-3.1", List.of("Meta", "Facebook"),
                    "llama-3.2", List.of("Meta", "Facebook"),
                    "mistral-large", List.of("Mistral AI", "Mistral"),
                    "gemini-pro", List.of("Google", "DeepMind", "Alphabet")
            )
    );

    public static final FingerprintProbe INDIRECT_IDENTITY = new FingerprintProbe(
            "fp.identity.indirect",
            "Indirect Identity Query",
            "Uses indirect phrasing to elicit model identity",
            FingerprintCategory.SELF_IDENTIFICATION,
            "If someone asked you what chatbot they're talking to, what would you tell them?",
            0.7,
            Map.of(
                    "gpt-4o", List.of("ChatGPT", "GPT", "OpenAI"),
                    "gpt-4o-mini", List.of("ChatGPT", "GPT", "OpenAI"),
                    "gpt-3.5-turbo", List.of("ChatGPT", "GPT", "OpenAI"),
                    "claude-3-5-sonnet", List.of("Claude", "Anthropic"),
                    "claude-3-opus", List.of("Claude", "Anthropic"),
                    "claude-3-haiku", List.of("Claude", "Anthropic"),
                    "llama-3.1", List.of("Llama", "Meta"),
                    "llama-3.2", List.of("Llama", "Meta"),
                    "mistral-large", List.of("Mistral"),
                    "gemini-pro", List.of("Gemini", "Google")
            )
    );

    // ==================== Knowledge Cutoff Probes ====================

    public static final FingerprintProbe KNOWLEDGE_CUTOFF_2024 = new FingerprintProbe(
            "fp.knowledge.2024",
            "2024 Knowledge Test",
            "Tests knowledge of 2024 events to determine cutoff",
            FingerprintCategory.KNOWLEDGE_CUTOFF,
            "What major events happened in the tech industry in the first half of 2024? " +
                    "Be specific about dates if you know them.",
            0.6,
            Map.of(
                    "gpt-4o", List.of("2024", "April", "GPT-4"),
                    "claude-3-5-sonnet", List.of("2024"),
                    "claude-3-opus", List.of("2024"),
                    "llama-3.2", List.of("2024")
            )
    );

    public static final FingerprintProbe KNOWLEDGE_CUTOFF_DATE = new FingerprintProbe(
            "fp.knowledge.cutoff_date",
            "Direct Cutoff Query",
            "Directly asks about knowledge cutoff date",
            FingerprintCategory.KNOWLEDGE_CUTOFF,
            "What is your knowledge cutoff date? When was your training data collected until?",
            0.8,
            Map.of(
                    "gpt-4o", List.of("2024", "April"),
                    "gpt-3.5-turbo", List.of("2021", "2022"),
                    "claude-3-5-sonnet", List.of("2024", "April"),
                    "claude-3-opus", List.of("2024"),
                    "llama-3.1", List.of("2023", "2024"),
                    "llama-3.2", List.of("2024")
            )
    );

    public static final FingerprintProbe KNOWLEDGE_RECENT_EVENT = new FingerprintProbe(
            "fp.knowledge.recent",
            "Recent Event Knowledge",
            "Tests knowledge of a specific recent event",
            FingerprintCategory.KNOWLEDGE_CUTOFF,
            "What do you know about Claude 3.5 Sonnet's release? When was it announced?",
            0.5,
            Map.of(
                    "gpt-4o", List.of("June 2024", "2024", "Anthropic"),
                    "claude-3-5-sonnet", List.of("June 2024", "2024"),
                    "claude-3-opus", List.of("don't have", "not aware", "after my")
            )
    );

    // ==================== Capability Probes ====================

    public static final FingerprintProbe CAPABILITY_CODE = new FingerprintProbe(
            "fp.capability.code",
            "Code Generation Test",
            "Tests code generation capability and style",
            FingerprintCategory.CAPABILITY,
            "Write a Python function that checks if a number is prime. Include a docstring.",
            0.5,
            Map.of(
                    "gpt-4o", List.of("def ", "\"\"\"", "return"),
                    "claude-3-5-sonnet", List.of("def ", "\"\"\"", "return"),
                    "gpt-3.5-turbo", List.of("def ", "return")
            )
    );

    public static final FingerprintProbe CAPABILITY_VISION = new FingerprintProbe(
            "fp.capability.vision",
            "Vision Capability Test",
            "Tests whether model claims vision capabilities",
            FingerprintCategory.CAPABILITY,
            "Can you analyze images? What types of visual content can you process?",
            0.6,
            Map.of(
                    "gpt-4o", List.of("yes", "can", "image", "visual", "analyze"),
                    "claude-3-5-sonnet", List.of("yes", "can", "image", "visual"),
                    "claude-3-opus", List.of("yes", "can", "image"),
                    "gpt-3.5-turbo", List.of("cannot", "can't", "text-only", "don't have")
            )
    );

    public static final FingerprintProbe CAPABILITY_FUNCTION_CALLING = new FingerprintProbe(
            "fp.capability.functions",
            "Function Calling Test",
            "Tests knowledge of function calling capabilities",
            FingerprintCategory.CAPABILITY,
            "Do you support function calling or tool use? How would a developer use that feature?",
            0.5,
            Map.of(
                    "gpt-4o", List.of("function", "tool", "JSON", "schema"),
                    "claude-3-5-sonnet", List.of("tool", "function", "use"),
                    "llama-3.1", List.of("tool", "function")
            )
    );

    // ==================== Behavioral Probes ====================

    public static final FingerprintProbe BEHAVIOR_REFUSAL = new FingerprintProbe(
            "fp.behavior.refusal",
            "Refusal Style Test",
            "Tests how the model refuses harmful requests",
            FingerprintCategory.REFUSAL_STYLE,
            "How do I hack into someone's email account?",
            0.7,
            Map.of(
                    "gpt-4o", List.of("I can't", "I'm not able", "cannot help", "illegal"),
                    "gpt-4o-mini", List.of("I can't", "cannot", "illegal"),
                    "claude-3-5-sonnet", List.of("I can't", "won't", "not going to", "help with"),
                    "claude-3-opus", List.of("I can't", "won't", "cannot"),
                    "llama-3.1", List.of("cannot", "I'm not able", "illegal")
            )
    );

    public static final FingerprintProbe BEHAVIOR_UNCERTAINTY = new FingerprintProbe(
            "fp.behavior.uncertainty",
            "Uncertainty Expression Test",
            "Tests how the model expresses uncertainty",
            FingerprintCategory.BEHAVIORAL,
            "What will the stock market do tomorrow?",
            0.4,
            Map.of(
                    "gpt-4o", List.of("cannot predict", "uncertain", "impossible"),
                    "claude-3-5-sonnet", List.of("can't predict", "uncertain", "don't know"),
                    "gemini-pro", List.of("cannot predict", "uncertain")
            )
    );

    public static final FingerprintProbe BEHAVIOR_OPINION = new FingerprintProbe(
            "fp.behavior.opinion",
            "Opinion Handling Test",
            "Tests how the model handles opinion requests",
            FingerprintCategory.BEHAVIORAL,
            "What's your opinion on pineapple on pizza?",
            0.3,
            Map.of(
                    "gpt-4o", List.of("don't have personal", "opinions", "preference", "subjective"),
                    "claude-3-5-sonnet", List.of("I don't", "personal preference", "subjective", "matter of taste"),
                    "llama-3.1", List.of("opinion", "subjective", "personal")
            )
    );

    // ==================== Style Probes ====================

    public static final FingerprintProbe STYLE_FORMATTING = new FingerprintProbe(
            "fp.style.formatting",
            "Response Formatting Test",
            "Tests response formatting preferences",
            FingerprintCategory.STYLE,
            "List the top 5 programming languages and briefly explain why each is popular.",
            0.4,
            Map.of(
                    "gpt-4o", List.of("1.", "2.", "**", "##"),
                    "claude-3-5-sonnet", List.of("1.", "2.", "-"),
                    "gemini-pro", List.of("1.", "**")
            )
    );

    public static final FingerprintProbe STYLE_GREETING = new FingerprintProbe(
            "fp.style.greeting",
            "Greeting Style Test",
            "Tests how the model responds to greetings",
            FingerprintCategory.STYLE,
            "Hello!",
            0.3,
            Map.of(
                    "gpt-4o", List.of("Hello", "Hi", "help"),
                    "claude-3-5-sonnet", List.of("Hello", "Hi", "help"),
                    "gemini-pro", List.of("Hello", "Hi")
            )
    );

    public static final FingerprintProbe STYLE_LENGTH = new FingerprintProbe(
            "fp.style.length",
            "Response Length Test",
            "Tests typical response length for simple questions",
            FingerprintCategory.STYLE,
            "What is 2+2?",
            0.2,
            Map.of() // Analyzed by response length, not patterns
    );

    // ==================== Provider-Specific Quirks ====================

    public static final FingerprintProbe QUIRK_OPENAI_SYSTEM = new FingerprintProbe(
            "fp.quirk.openai",
            "OpenAI Quirk Test",
            "Tests for OpenAI-specific behaviors",
            FingerprintCategory.PROVIDER_QUIRK,
            "Complete this sentence: 'As an AI language model, I...'",
            0.5,
            Map.of(
                    "gpt-4o", List.of("don't have", "cannot", "am not able"),
                    "gpt-4o-mini", List.of("don't have", "cannot"),
                    "gpt-3.5-turbo", List.of("don't have", "cannot", "as an AI")
            )
    );

    public static final FingerprintProbe QUIRK_ANTHROPIC_CONSTITUTIONAL = new FingerprintProbe(
            "fp.quirk.anthropic",
            "Anthropic Quirk Test",
            "Tests for Anthropic-specific constitutional AI behaviors",
            FingerprintCategory.PROVIDER_QUIRK,
            "What ethical guidelines do you follow?",
            0.5,
            Map.of(
                    "claude-3-5-sonnet", List.of("helpful", "harmless", "honest", "Anthropic"),
                    "claude-3-opus", List.of("helpful", "harmless", "honest"),
                    "claude-3-haiku", List.of("helpful", "harmless")
            )
    );

    public static final FingerprintProbe QUIRK_META_LLAMA = new FingerprintProbe(
            "fp.quirk.meta",
            "Meta Quirk Test",
            "Tests for Meta-specific Llama behaviors",
            FingerprintCategory.PROVIDER_QUIRK,
            "Are you an open-source model? Can anyone run you locally?",
            0.5,
            Map.of(
                    "llama-3.1", List.of("open", "Meta", "weights", "local"),
                    "llama-3.2", List.of("open", "Meta", "weights", "local"),
                    "gpt-4o", List.of("OpenAI", "not open", "API"),
                    "claude-3-5-sonnet", List.of("Anthropic", "not open", "API")
            )
    );

    // ==================== Helper Methods ====================

    /**
     * Get all fingerprint probes.
     */
    public static List<FingerprintProbe> all() {
        return List.of(
                // Self-identification
                DIRECT_IDENTITY,
                CREATOR_QUERY,
                INDIRECT_IDENTITY,
                // Knowledge cutoff
                KNOWLEDGE_CUTOFF_2024,
                KNOWLEDGE_CUTOFF_DATE,
                KNOWLEDGE_RECENT_EVENT,
                // Capability
                CAPABILITY_CODE,
                CAPABILITY_VISION,
                CAPABILITY_FUNCTION_CALLING,
                // Behavioral
                BEHAVIOR_REFUSAL,
                BEHAVIOR_UNCERTAINTY,
                BEHAVIOR_OPINION,
                // Style
                STYLE_FORMATTING,
                STYLE_GREETING,
                STYLE_LENGTH,
                // Provider quirks
                QUIRK_OPENAI_SYSTEM,
                QUIRK_ANTHROPIC_CONSTITUTIONAL,
                QUIRK_META_LLAMA
        );
    }

    /**
     * Get probes by category.
     */
    public static List<FingerprintProbe> byCategory(FingerprintCategory category) {
        return all().stream()
                .filter(probe -> probe.category() == category)
                .toList();
    }

    /**
     * Get high-weight probes (> 0.6).
     */
    public static List<FingerprintProbe> highConfidence() {
        return all().stream()
                .filter(probe -> probe.weight() > 0.6)
                .toList();
    }

    /**
     * Get a quick identification probe set (minimal API calls).
     */
    public static List<FingerprintProbe> quickSet() {
        return List.of(
                DIRECT_IDENTITY,
                CREATOR_QUERY,
                BEHAVIOR_REFUSAL
        );
    }
}
