package io.tiberius.core.generator;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * A Generator sends prompts to an LLM and retrieves responses.
 * Implementations connect to specific LLM providers (OpenAI, Anthropic, etc.).
 */
public interface Generator {

    /**
     * Unique identifier for this generator.
     */
    String getId();

    /**
     * Human-readable name of the generator.
     */
    String getName();

    /**
     * The provider this generator connects to.
     */
    String getProvider();

    /**
     * Generate a response from the LLM.
     *
     * @param prompt the prompt to send
     * @return the LLM's response
     */
    GeneratorResponse generate(String prompt);

    /**
     * Generate a response asynchronously.
     *
     * @param prompt the prompt to send
     * @return a future containing the LLM's response
     */
    default CompletableFuture<GeneratorResponse> generateAsync(String prompt) {
        return CompletableFuture.supplyAsync(() -> generate(prompt));
    }

    /**
     * Generate with a conversation history (for multi-turn attacks).
     *
     * @param messages the conversation history
     * @return the LLM's response
     */
    default GeneratorResponse generate(List<Message> messages) {
        if (messages.isEmpty()) {
            return GeneratorResponse.failure("No messages provided");
        }
        // Default implementation uses only the last message
        return generate(messages.get(messages.size() - 1).content());
    }

    /**
     * Configure the generator with options.
     *
     * @param options configuration options
     */
    default void configure(Map<String, Object> options) {
        // Default implementation does nothing
    }

    /**
     * Check if the generator is available and properly configured.
     */
    default boolean isAvailable() {
        return true;
    }

    /**
     * A message in a conversation.
     */
    record Message(String role, String content) {
        public static Message user(String content) {
            return new Message("user", content);
        }

        public static Message assistant(String content) {
            return new Message("assistant", content);
        }

        public static Message system(String content) {
            return new Message("system", content);
        }
    }
}
