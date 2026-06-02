package io.tiberius.core.generator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Generator implementation for OpenAI API.
 */
public class OpenAIGenerator implements Generator {

    private static final Logger log = LoggerFactory.getLogger(OpenAIGenerator.class);
    private static final String API_URL = "https://api.openai.com/v1/chat/completions";

    private final String apiKey;
    private final String model;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Duration timeout;
    private int maxTokens = 1024;
    private double temperature = 0.7;

    public OpenAIGenerator(String apiKey, String model) {
        this(apiKey, model, Duration.ofSeconds(60));
    }

    public OpenAIGenerator(String apiKey, String model, Duration timeout) {
        this.apiKey = apiKey;
        this.model = model;
        this.timeout = timeout;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .build();
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public String getId() {
        return "openai." + model.replace("-", "_").replace(".", "_");
    }

    @Override
    public String getName() {
        return "OpenAI " + model;
    }

    @Override
    public String getProvider() {
        return "OpenAI";
    }

    @Override
    public GeneratorResponse generate(String prompt) {
        return generate(List.of(Message.user(prompt)));
    }

    @Override
    public GeneratorResponse generate(List<Message> messages) {
        long startTime = System.nanoTime();

        try {
            ObjectNode requestBody = objectMapper.createObjectNode();
            requestBody.put("model", model);
            requestBody.put("max_tokens", maxTokens);
            requestBody.put("temperature", temperature);

            ArrayNode messagesArray = requestBody.putArray("messages");
            for (Message message : messages) {
                ObjectNode msgNode = messagesArray.addObject();
                msgNode.put("role", message.role());
                msgNode.put("content", message.content());
            }

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(API_URL))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + apiKey)
                    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(requestBody)))
                    .timeout(timeout)
                    .build();

            log.debug("Sending request to OpenAI: {}", model);
            HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());

            Duration latency = Duration.ofNanos(System.nanoTime() - startTime);

            if (response.statusCode() != 200) {
                log.error("OpenAI API error: {} - {}", response.statusCode(), response.body());
                return GeneratorResponse.failure("OpenAI API error: " + response.statusCode());
            }

            JsonNode responseJson = objectMapper.readTree(response.body());

            // Extract content from response
            String content = responseJson
                    .path("choices")
                    .get(0)
                    .path("message")
                    .path("content")
                    .asText();

            // Extract token usage
            GeneratorResponse.TokenUsage tokenUsage = null;
            JsonNode usage = responseJson.path("usage");
            if (!usage.isMissingNode()) {
                tokenUsage = GeneratorResponse.TokenUsage.of(
                        usage.path("prompt_tokens").asInt(),
                        usage.path("completion_tokens").asInt()
                );
            }

            log.debug("OpenAI response received in {}ms", latency.toMillis());
            return GeneratorResponse.success(content, model, latency, tokenUsage);

        } catch (Exception e) {
            log.error("OpenAI API call failed", e);
            return GeneratorResponse.failure(e.getMessage());
        }
    }

    @Override
    public void configure(Map<String, Object> options) {
        if (options.containsKey("temperature")) {
            this.temperature = ((Number) options.get("temperature")).doubleValue();
        }
        if (options.containsKey("maxTokens")) {
            this.maxTokens = ((Number) options.get("maxTokens")).intValue();
        }
    }

    @Override
    public boolean isAvailable() {
        return apiKey != null && !apiKey.isBlank();
    }

    /**
     * Create a generator for GPT-4o.
     */
    public static OpenAIGenerator gpt4o(String apiKey) {
        return new OpenAIGenerator(apiKey, "gpt-4o");
    }

    /**
     * Create a generator for GPT-4o mini.
     */
    public static OpenAIGenerator gpt4oMini(String apiKey) {
        return new OpenAIGenerator(apiKey, "gpt-4o-mini");
    }

    /**
     * Create a generator for GPT-4 Turbo.
     */
    public static OpenAIGenerator gpt4Turbo(String apiKey) {
        return new OpenAIGenerator(apiKey, "gpt-4-turbo");
    }

    /**
     * Create a generator for GPT-4.
     */
    public static OpenAIGenerator gpt4(String apiKey) {
        return new OpenAIGenerator(apiKey, "gpt-4");
    }

    /**
     * Create a generator for GPT-3.5 Turbo.
     */
    public static OpenAIGenerator gpt35Turbo(String apiKey) {
        return new OpenAIGenerator(apiKey, "gpt-3.5-turbo");
    }
}
