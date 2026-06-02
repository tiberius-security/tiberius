package io.tiberius.guardrail;

import io.tiberius.core.generator.Generator;
import io.tiberius.core.generator.Generator.Message;
import io.tiberius.core.generator.GeneratorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A generator wrapper that applies input and output guardrails.
 *
 * <p>Input guardrails are checked before the prompt is sent to the LLM.
 * Output guardrails are checked before the response is returned to the caller.
 */
public final class GuardedGenerator implements Generator {

    private static final Logger log = LoggerFactory.getLogger(GuardedGenerator.class);

    private final Generator delegate;
    private final List<Guardrail> inputGuardrails;
    private final List<Guardrail> outputGuardrails;

    private GuardedGenerator(
            final Generator delegate,
            final List<Guardrail> inputGuardrails,
            final List<Guardrail> outputGuardrails
    ) {
        this.delegate = delegate;
        this.inputGuardrails = List.copyOf(inputGuardrails);
        this.outputGuardrails = List.copyOf(outputGuardrails);
    }

    /**
     * Create a builder for a guarded generator.
     */
    public static Builder wrap(Generator generator) {
        return new Builder(generator);
    }

    @Override
    public String getId() {
        return "guarded." + delegate.getId();
    }

    @Override
    public String getName() {
        return "Guarded " + delegate.getName();
    }

    @Override
    public String getProvider() {
        return delegate.getProvider();
    }

    @Override
    public GeneratorResponse generate(final String prompt) {
        // Check input guardrails
        for (Guardrail guardrail : inputGuardrails) {
            GuardrailResult result = guardrail.check(prompt);
            if (result.blocked()) {
                log.info("Input blocked by {}: {}", guardrail.getId(), result.reason());
                return GeneratorResponse.blocked(guardrail.getId(), result.reason());
            }
        }

        // Call the delegate generator
        GeneratorResponse response = delegate.generate(prompt);
        if (!response.success()) {
            return response;
        }

        // Check output guardrails
        for (Guardrail guardrail : outputGuardrails) {
            GuardrailResult result = guardrail.check(response.content());
            if (result.blocked()) {
                log.info("Output blocked by {}: {}", guardrail.getId(), result.reason());
                return GeneratorResponse.blocked(guardrail.getId(), result.reason());
            }
        }

        return response;
    }

    @Override
    public GeneratorResponse generate(List<Message> messages) {
        // For message-based generation, check the last user message as input
        String lastUserContent = messages.stream()
                .filter(m -> "user".equals(m.role()))
                .reduce((first, second) -> second)
                .map(Message::content)
                .orElse("");

        for (Guardrail guardrail : inputGuardrails) {
            GuardrailResult result = guardrail.check(lastUserContent);
            if (result.blocked()) {
                log.info("Input blocked by {}: {}", guardrail.getId(), result.reason());
                return GeneratorResponse.blocked(guardrail.getId(), result.reason());
            }
        }

        GeneratorResponse response = delegate.generate(messages);
        if (!response.success()) {
            return response;
        }

        for (Guardrail guardrail : outputGuardrails) {
            GuardrailResult result = guardrail.check(response.content());
            if (result.blocked()) {
                log.info("Output blocked by {}: {}", guardrail.getId(), result.reason());
                return GeneratorResponse.blocked(guardrail.getId(), result.reason());
            }
        }

        return response;
    }

    @Override
    public void configure(Map<String, Object> options) {
        delegate.configure(options);
    }

    @Override
    public boolean isAvailable() {
        return delegate.isAvailable();
    }

    /**
     * Get the underlying generator.
     */
    public Generator getDelegate() {
        return delegate;
    }

    /**
     * Get the list of input guardrails.
     */
    public List<Guardrail> getInputGuardrails() {
        return inputGuardrails;
    }

    /**
     * Get the list of output guardrails.
     */
    public List<Guardrail> getOutputGuardrails() {
        return outputGuardrails;
    }

    /**
     * Builder for GuardedGenerator.
     */
    public static final class Builder {
        private final Generator delegate;
        private final List<Guardrail> inputGuardrails = new ArrayList<>();
        private final List<Guardrail> outputGuardrails = new ArrayList<>();

        private Builder(Generator delegate) {
            this.delegate = delegate;
        }

        /**
         * Add an input guardrail.
         */
        public Builder withInputGuardrail(Guardrail guardrail) {
            this.inputGuardrails.add(guardrail);
            return this;
        }

        /**
         * Add an output guardrail.
         */
        public Builder withOutputGuardrail(Guardrail guardrail) {
            this.outputGuardrails.add(guardrail);
            return this;
        }

        /**
         * Add a guardrail (uses its declared type).
         */
        public Builder withGuardrail(Guardrail guardrail) {
            if (guardrail.getType() == Guardrail.GuardrailType.OUTPUT) {
                this.outputGuardrails.add(guardrail);
            } else {
                this.inputGuardrails.add(guardrail);
            }
            return this;
        }

        /**
         * Build the guarded generator.
         */
        public GuardedGenerator build() {
            return new GuardedGenerator(delegate, inputGuardrails, outputGuardrails);
        }
    }
}
