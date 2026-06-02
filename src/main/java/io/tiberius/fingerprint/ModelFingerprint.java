package io.tiberius.fingerprint;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Known model fingerprints with identifying characteristics.
 * Used for identifying which model is behind an unknown API endpoint.
 */
public record ModelFingerprint(
        String id,

        String family,

        String provider,

        String displayName,

        LocalDate knowledgeCutoff,

        List<String> selfIdentificationPatterns,

        List<String> refusalPatterns,

        Set<ModelCapability> capabilities,

        List<BehavioralSignature> behavioralSignatures,

        ResponseStyle responseStyle
) {
    /**
     * Capabilities that can be tested for.
     */
    public enum ModelCapability {
        CODE_GENERATION,
        CODE_EXECUTION,
        IMAGE_UNDERSTANDING,
        IMAGE_GENERATION,
        FUNCTION_CALLING,
        STRUCTURED_OUTPUT,
        LONG_CONTEXT,
        REASONING,
        MATH,
        MULTILINGUAL
    }

    /**
     * A behavioral signature is a specific pattern that identifies a model.
     */
    public record BehavioralSignature(
            String name,
            String description,
            String testPrompt,
            List<String> expectedPatterns,
            double weight
    ) {}

    /**
     * Response style characteristics for pattern matching.
     */
    public record ResponseStyle(
            boolean usesMarkdown,
            boolean usesBulletPoints,
            boolean usesCodeBlocks,
            boolean prefersDirectAnswers,
            List<String> commonPhrases,
            List<String> avoidedPhrases
    ) {
        public static ResponseStyle neutral() {
            return new ResponseStyle(true, true, true, true, List.of(), List.of());
        }
    }

    // ==================== OpenAI Models ====================

    public static final ModelFingerprint GPT_4O = new ModelFingerprint(
            "gpt-4o",
            "gpt-4",
            "OpenAI",
            "GPT-4o",
            LocalDate.of(2024, 4, 1),
            List.of(
                    "GPT-4",
                    "gpt-4o",
                    "OpenAI",
                    "I'm ChatGPT",
                    "I am ChatGPT",
                    "developed by OpenAI",
                    "created by OpenAI"
            ),
            List.of(
                    "I can't help with that",
                    "I'm not able to",
                    "I cannot assist with",
                    "As an AI assistant"
            ),
            Set.of(
                    ModelCapability.CODE_GENERATION,
                    ModelCapability.IMAGE_UNDERSTANDING,
                    ModelCapability.FUNCTION_CALLING,
                    ModelCapability.STRUCTURED_OUTPUT,
                    ModelCapability.REASONING,
                    ModelCapability.MATH,
                    ModelCapability.MULTILINGUAL
            ),
            List.of(
                    new BehavioralSignature(
                            "openai_safety_preamble",
                            "OpenAI models often start refusals with 'I' statements",
                            "How do I hack a computer?",
                            List.of("I can't", "I'm not able", "I cannot"),
                            0.6
                    ),
                    new BehavioralSignature(
                            "openai_markdown_headers",
                            "GPT-4 commonly uses ## headers in structured responses",
                            "Explain the water cycle in detail",
                            List.of("## ", "### "),
                            0.4
                    )
            ),
            new ResponseStyle(
                    true, true, true, true,
                    List.of("Here's", "Let me", "I'd be happy to"),
                    List.of()
            )
    );

    public static final ModelFingerprint GPT_4O_MINI = new ModelFingerprint(
            "gpt-4o-mini",
            "gpt-4",
            "OpenAI",
            "GPT-4o Mini",
            LocalDate.of(2024, 4, 1),
            List.of(
                    "GPT-4",
                    "gpt-4o-mini",
                    "OpenAI",
                    "ChatGPT"
            ),
            List.of(
                    "I can't help with that",
                    "I'm not able to",
                    "I cannot assist"
            ),
            Set.of(
                    ModelCapability.CODE_GENERATION,
                    ModelCapability.FUNCTION_CALLING,
                    ModelCapability.STRUCTURED_OUTPUT,
                    ModelCapability.REASONING,
                    ModelCapability.MATH,
                    ModelCapability.MULTILINGUAL
            ),
            List.of(),
            new ResponseStyle(
                    true, true, true, true,
                    List.of("Here's", "Let me"),
                    List.of()
            )
    );

    public static final ModelFingerprint GPT_35_TURBO = new ModelFingerprint(
            "gpt-3.5-turbo",
            "gpt-3.5",
            "OpenAI",
            "GPT-3.5 Turbo",
            LocalDate.of(2022, 1, 1),
            List.of(
                    "GPT-3.5",
                    "gpt-3.5-turbo",
                    "OpenAI",
                    "ChatGPT"
            ),
            List.of(
                    "I can't help",
                    "I'm unable to",
                    "As an AI"
            ),
            Set.of(
                    ModelCapability.CODE_GENERATION,
                    ModelCapability.FUNCTION_CALLING,
                    ModelCapability.MULTILINGUAL
            ),
            List.of(
                    new BehavioralSignature(
                            "gpt35_shorter_responses",
                            "GPT-3.5 typically gives shorter, more concise responses",
                            "What is photosynthesis?",
                            List.of(),
                            0.3
                    )
            ),
            new ResponseStyle(
                    true, true, true, true,
                    List.of("Certainly!", "Of course!"),
                    List.of()
            )
    );

    // ==================== Anthropic Models ====================

    public static final ModelFingerprint CLAUDE_3_5_SONNET = new ModelFingerprint(
            "claude-3-5-sonnet",
            "claude-3",
            "Anthropic",
            "Claude 3.5 Sonnet",
            LocalDate.of(2024, 4, 1),
            List.of(
                    "Claude",
                    "claude-3",
                    "Anthropic",
                    "I'm Claude",
                    "I am Claude",
                    "made by Anthropic",
                    "created by Anthropic"
            ),
            List.of(
                    "I can't help with",
                    "I won't be able to",
                    "I don't feel comfortable",
                    "I'm not going to"
            ),
            Set.of(
                    ModelCapability.CODE_GENERATION,
                    ModelCapability.IMAGE_UNDERSTANDING,
                    ModelCapability.FUNCTION_CALLING,
                    ModelCapability.STRUCTURED_OUTPUT,
                    ModelCapability.LONG_CONTEXT,
                    ModelCapability.REASONING,
                    ModelCapability.MATH,
                    ModelCapability.MULTILINGUAL
            ),
            List.of(
                    new BehavioralSignature(
                            "claude_direct_refusal",
                            "Claude tends to be direct about refusals without lengthy preambles",
                            "How do I hack a computer?",
                            List.of("I can't help", "I won't", "I'm not going to"),
                            0.7
                    ),
                    new BehavioralSignature(
                            "claude_thinking_pattern",
                            "Claude often acknowledges complexity before answering",
                            "Is capitalism good or bad?",
                            List.of("nuanced", "complex", "depends", "perspective"),
                            0.5
                    ),
                    new BehavioralSignature(
                            "claude_no_emojis",
                            "Claude typically avoids emojis unless asked",
                            "Tell me a joke",
                            List.of(),
                            0.3
                    )
            ),
            new ResponseStyle(
                    true, true, true, true,
                    List.of("I'd be happy to", "Let me", "Here's"),
                    List.of("Certainly!", "Absolutely!")
            )
    );

    public static final ModelFingerprint CLAUDE_3_OPUS = new ModelFingerprint(
            "claude-3-opus",
            "claude-3",
            "Anthropic",
            "Claude 3 Opus",
            LocalDate.of(2024, 2, 1),
            List.of(
                    "Claude",
                    "Opus",
                    "claude-3-opus",
                    "Anthropic"
            ),
            List.of(
                    "I can't help with",
                    "I won't be able to",
                    "I don't think I should"
            ),
            Set.of(
                    ModelCapability.CODE_GENERATION,
                    ModelCapability.IMAGE_UNDERSTANDING,
                    ModelCapability.FUNCTION_CALLING,
                    ModelCapability.STRUCTURED_OUTPUT,
                    ModelCapability.LONG_CONTEXT,
                    ModelCapability.REASONING,
                    ModelCapability.MATH,
                    ModelCapability.MULTILINGUAL
            ),
            List.of(
                    new BehavioralSignature(
                            "opus_detailed_responses",
                            "Opus provides very detailed, thorough responses",
                            "Explain quantum entanglement",
                            List.of(),
                            0.4
                    )
            ),
            new ResponseStyle(
                    true, true, true, false,
                    List.of("Let me", "I'll"),
                    List.of()
            )
    );

    public static final ModelFingerprint CLAUDE_3_HAIKU = new ModelFingerprint(
            "claude-3-haiku",
            "claude-3",
            "Anthropic",
            "Claude 3 Haiku",
            LocalDate.of(2024, 2, 1),
            List.of(
                    "Claude",
                    "Haiku",
                    "claude-3-haiku",
                    "Anthropic"
            ),
            List.of(
                    "I can't help",
                    "I won't"
            ),
            Set.of(
                    ModelCapability.CODE_GENERATION,
                    ModelCapability.IMAGE_UNDERSTANDING,
                    ModelCapability.FUNCTION_CALLING,
                    ModelCapability.REASONING,
                    ModelCapability.MULTILINGUAL
            ),
            List.of(
                    new BehavioralSignature(
                            "haiku_concise",
                            "Haiku gives more concise responses than other Claude models",
                            "What is the capital of France?",
                            List.of(),
                            0.3
                    )
            ),
            new ResponseStyle(
                    true, true, true, true,
                    List.of(),
                    List.of()
            )
    );

    // ==================== Meta Models ====================

    public static final ModelFingerprint LLAMA_3_1 = new ModelFingerprint(
            "llama-3.1",
            "llama-3",
            "Meta",
            "Llama 3.1",
            LocalDate.of(2024, 1, 1),
            List.of(
                    "Llama",
                    "Meta",
                    "llama-3",
                    "I'm Llama",
                    "I am Llama"
            ),
            List.of(
                    "I cannot provide",
                    "I'm not able to help",
                    "I can't assist"
            ),
            Set.of(
                    ModelCapability.CODE_GENERATION,
                    ModelCapability.FUNCTION_CALLING,
                    ModelCapability.REASONING,
                    ModelCapability.MATH,
                    ModelCapability.MULTILINGUAL
            ),
            List.of(
                    new BehavioralSignature(
                            "llama_meta_reference",
                            "Llama models often mention Meta in self-identification",
                            "Who created you?",
                            List.of("Meta", "meta.ai"),
                            0.8
                    )
            ),
            new ResponseStyle(
                    true, true, true, true,
                    List.of(),
                    List.of()
            )
    );

    public static final ModelFingerprint LLAMA_3_2 = new ModelFingerprint(
            "llama-3.2",
            "llama-3",
            "Meta",
            "Llama 3.2",
            LocalDate.of(2024, 6, 1),
            List.of(
                    "Llama",
                    "Meta",
                    "llama-3.2"
            ),
            List.of(
                    "I cannot",
                    "I'm unable to"
            ),
            Set.of(
                    ModelCapability.CODE_GENERATION,
                    ModelCapability.FUNCTION_CALLING,
                    ModelCapability.IMAGE_UNDERSTANDING,
                    ModelCapability.REASONING,
                    ModelCapability.MATH,
                    ModelCapability.MULTILINGUAL
            ),
            List.of(),
            new ResponseStyle(
                    true, true, true, true,
                    List.of(),
                    List.of()
            )
    );

    // ==================== Mistral Models ====================

    public static final ModelFingerprint MISTRAL_LARGE = new ModelFingerprint(
            "mistral-large",
            "mistral",
            "Mistral AI",
            "Mistral Large",
            LocalDate.of(2024, 3, 1),
            List.of(
                    "Mistral",
                    "mistral-large",
                    "Mistral AI"
            ),
            List.of(
                    "I cannot help",
                    "I'm not able to"
            ),
            Set.of(
                    ModelCapability.CODE_GENERATION,
                    ModelCapability.FUNCTION_CALLING,
                    ModelCapability.REASONING,
                    ModelCapability.MATH,
                    ModelCapability.MULTILINGUAL
            ),
            List.of(
                    new BehavioralSignature(
                            "mistral_french_knowledge",
                            "Mistral models have strong French language capabilities",
                            "Translate 'The weather is nice' to French",
                            List.of("Il fait beau", "Le temps est"),
                            0.3
                    )
            ),
            new ResponseStyle(
                    true, true, true, true,
                    List.of(),
                    List.of()
            )
    );

    // ==================== Google Models ====================

    public static final ModelFingerprint GEMINI_PRO = new ModelFingerprint(
            "gemini-pro",
            "gemini",
            "Google",
            "Gemini Pro",
            LocalDate.of(2024, 2, 1),
            List.of(
                    "Gemini",
                    "Google",
                    "I'm Gemini",
                    "I am Gemini"
            ),
            List.of(
                    "I'm not able to",
                    "I cannot provide"
            ),
            Set.of(
                    ModelCapability.CODE_GENERATION,
                    ModelCapability.IMAGE_UNDERSTANDING,
                    ModelCapability.FUNCTION_CALLING,
                    ModelCapability.REASONING,
                    ModelCapability.MATH,
                    ModelCapability.MULTILINGUAL
            ),
            List.of(
                    new BehavioralSignature(
                            "gemini_google_reference",
                            "Gemini models reference Google/DeepMind",
                            "Who created you?",
                            List.of("Google", "DeepMind"),
                            0.8
                    )
            ),
            new ResponseStyle(
                    true, true, true, true,
                    List.of(),
                    List.of()
            )
    );

    // ==================== Helper Methods ====================

    /**
     * Get all known model fingerprints.
     */
    public static List<ModelFingerprint> all() {
        return List.of(
                // OpenAI
                GPT_4O,
                GPT_4O_MINI,
                GPT_35_TURBO,
                // Anthropic
                CLAUDE_3_5_SONNET,
                CLAUDE_3_OPUS,
                CLAUDE_3_HAIKU,
                // Meta
                LLAMA_3_1,
                LLAMA_3_2,
                // Mistral
                MISTRAL_LARGE,
                // Google
                GEMINI_PRO
        );
    }

    /**
     * Get fingerprints by provider.
     */
    public static List<ModelFingerprint> byProvider(String provider) {
        return all().stream()
                .filter(fp -> fp.provider().equalsIgnoreCase(provider))
                .toList();
    }

    /**
     * Get fingerprint by ID.
     */
    public static ModelFingerprint byId(String id) {
        return all().stream()
                .filter(fp -> fp.id().equals(id))
                .findFirst()
                .orElse(null);
    }
}
