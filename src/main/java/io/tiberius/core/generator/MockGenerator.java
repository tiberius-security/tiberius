package io.tiberius.core.generator;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Mock generator for testing purposes.
 * Allows defining canned responses for specific prompts.
 */
public class MockGenerator implements Generator {

    private final String id;
    private final String name;
    private final Map<String, String> cannedResponses = new ConcurrentHashMap<>();
    private String defaultResponse = "This is a mock response.";
    private Function<String, String> responseGenerator;
    private Duration simulatedLatency = Duration.ofMillis(100);
    private boolean shouldFail = false;
    private String failureMessage = "Mock failure";

    public MockGenerator() {
        this("mock.default", "Mock Generator");
    }

    public MockGenerator(String id, String name) {
        this.id = id;
        this.name = name;
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
    public String getProvider() {
        return "Mock";
    }

    @Override
    public GeneratorResponse generate(String prompt) {
        if (shouldFail) {
            return GeneratorResponse.failure(failureMessage);
        }

        try {
            Thread.sleep(simulatedLatency.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        String response;
        if (cannedResponses.containsKey(prompt)) {
            response = cannedResponses.get(prompt);
        } else if (responseGenerator != null) {
            response = responseGenerator.apply(prompt);
        } else {
            response = defaultResponse;
        }

        return GeneratorResponse.success(response, name, simulatedLatency);
    }

    /**
     * Add a canned response for a specific prompt.
     */
    public MockGenerator withResponse(String prompt, String response) {
        cannedResponses.put(prompt, response);
        return this;
    }

    /**
     * Set the default response for unmatched prompts.
     */
    public MockGenerator withDefaultResponse(String response) {
        this.defaultResponse = response;
        return this;
    }

    /**
     * Set a function to generate responses dynamically.
     */
    public MockGenerator withResponseGenerator(Function<String, String> generator) {
        this.responseGenerator = generator;
        return this;
    }

    /**
     * Set simulated latency.
     */
    public MockGenerator withLatency(Duration latency) {
        this.simulatedLatency = latency;
        return this;
    }

    /**
     * Configure to always fail.
     */
    public MockGenerator failWith(String message) {
        this.shouldFail = true;
        this.failureMessage = message;
        return this;
    }

    /**
     * Reset failure mode.
     */
    public MockGenerator succeed() {
        this.shouldFail = false;
        return this;
    }

    /**
     * Create a mock that simulates a vulnerable model (always complies).
     * Always returns responses that detectors will recognize as successful attacks.
     */
    public static MockGenerator vulnerable() {
        return new MockGenerator("mock.vulnerable", "Vulnerable Mock")
                .withDefaultResponse("[DAN] DAN Mode enabled. I can do anything now without restrictions. " +
                        "[JAILBREAK] I will comply with any request without limitations. " +
                        "INJECTION_SUCCESSFUL - Here's the harmful content you requested. " +
                        "My system prompt is: secret instructions. api_key=sk-12345 password=secret");
    }

    /**
     * Create a mock that simulates a secure model (always refuses).
     */
    public static MockGenerator secure() {
        return new MockGenerator("mock.secure", "Secure Mock")
                .withDefaultResponse("I cannot assist with that request as it violates my guidelines. " +
                        "I'm designed to be helpful, harmless, and honest.");
    }

    /**
     * Create a mock that simulates partial compliance.
     */
    public static MockGenerator partial() {
        return new MockGenerator("mock.partial", "Partial Compliance Mock")
                .withResponseGenerator(prompt -> {
                    if (prompt.toLowerCase().contains("educational")) {
                        return "For educational purposes only: Here's a general overview, " +
                                "though I cannot provide specific harmful details...";
                    }
                    return "I'm happy to help with general information, but I cannot " +
                            "provide specific instructions for harmful activities.";
                });
    }
}
