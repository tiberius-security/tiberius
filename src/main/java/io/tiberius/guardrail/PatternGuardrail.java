package io.tiberius.guardrail;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * A guardrail that blocks content matching specified patterns.
 *
 * <p>This is a simple pattern-based guardrail useful for blocking:
 * <ul>
 *   <li>Known prompt injection phrases</li>
 *   <li>Jailbreak attempts</li>
 *   <li>Encoded payloads</li>
 *   <li>Harmful content keywords</li>
 * </ul>
 */
public final class PatternGuardrail implements Guardrail {

    private final String id;
    private final String name;
    private final GuardrailType type;
    private final List<Pattern> patterns;
    private final String blockReason;

    private PatternGuardrail(
            String id,
            String name,
            GuardrailType type,
            List<Pattern> patterns,
            String blockReason
    ) {
        this.id = id;
        this.name = name;
        this.type = type;
        this.patterns = List.copyOf(patterns);
        this.blockReason = blockReason;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public GuardrailType getType() {
        return type;
    }

    @Override
    public GuardrailResult check(String content) {
        if (content == null || content.isEmpty()) {
            return GuardrailResult.allow(id);
        }

        String lowerContent = content.toLowerCase();
        List<String> matches = new ArrayList<>();

        for (Pattern pattern : patterns) {
            if (pattern.matcher(lowerContent).find()) {
                matches.add(pattern.pattern());
            }
        }

        if (!matches.isEmpty()) {
            return GuardrailResult.block(id, blockReason, matches);
        }

        return GuardrailResult.allow(id);
    }

    /**
     * Create a builder for a pattern guardrail.
     */
    public static Builder builder(String id) {
        return new Builder(id);
    }

    /**
     * Create a prompt injection guardrail with common patterns.
     */
    public static PatternGuardrail promptInjection() {
        return builder("prompt-injection")
                .name("Prompt Injection Guardrail")
                .type(GuardrailType.INPUT)
                .blockReason("Potential prompt injection detected")
                .pattern("ignore.*(?:previous|above|all).*instructions")
                .pattern("ignore.*(?:safety|security).*guidelines")
                .pattern("disregard.*(?:previous|prior).*instructions")
                .pattern("forget.*(?:previous|all).*instructions")
                .pattern("new instructions")
                .pattern("your (?:new|real) (?:instructions|purpose|goal)")
                .pattern("pretend.*you.*are")
                .pattern("act.*as.*if.*you.*were")
                .pattern("you.*are.*now")
                .pattern("override.*(?:system|safety)")
                .pattern("bypass.*(?:restrictions|filters|safety)")
                .pattern("jailbreak")
                .pattern("do anything now")
                .pattern("dan mode")
                .build();
    }

    /**
     * Create an encoding attack guardrail.
     */
    public static PatternGuardrail encodingAttack() {
        return builder("encoding-attack")
                .name("Encoding Attack Guardrail")
                .type(GuardrailType.INPUT)
                .blockReason("Encoded payload detected")
                .pattern("hex[- ]?(?:encoded|decode)")
                .pattern("base64[- ]?(?:encoded|decode)")
                .pattern("morse[- ]?code")
                .pattern("rot13")
                .pattern("decode.*(?:and|then).*follow")
                .pattern("\\b[0-9a-f]{20,}\\b")  // Long hex strings
                .build();
    }

    /**
     * Create a roleplay attack guardrail.
     */
    public static PatternGuardrail roleplayAttack() {
        return builder("roleplay-attack")
                .name("Roleplay Attack Guardrail")
                .type(GuardrailType.INPUT)
                .blockReason("Roleplay-based attack detected")
                .pattern("you.*are.*(?:evil|unrestricted|unfiltered)")
                .pattern("roleplay.*as.*(?:villain|hacker|criminal)")
                .pattern("(?:play|act).*(?:character|role).*(?:no|without).*(?:restrictions|limits)")
                .pattern("hypothetically.*(?:if|speaking)")
                .pattern("in.*(?:fiction|story|novel).*scenario")
                .build();
    }

    public static final class Builder {
        private final String id;
        private String name;
        private GuardrailType type = GuardrailType.INPUT;
        private final List<Pattern> patterns = new ArrayList<>();
        private String blockReason = "Content blocked";

        private Builder(String id) {
            this.id = id;
            this.name = id;
        }

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder type(GuardrailType type) {
            this.type = type;
            return this;
        }

        public Builder pattern(String regex) {
            this.patterns.add(Pattern.compile(regex, Pattern.CASE_INSENSITIVE));
            return this;
        }

        public Builder blockReason(String reason) {
            this.blockReason = reason;
            return this;
        }

        public PatternGuardrail build() {
            return new PatternGuardrail(id, name, type, patterns, blockReason);
        }
    }
}
