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
 * Generator implementation for Anthropic Claude API.
 */
public class AnthropicGenerator implements Generator {

    private static final Logger log = LoggerFactory.getLogger(AnthropicGenerator.class);
    private static final String API_URL = "https://api.anthropic.com/v1/messages";
    private static final String API_VERSION = "2023-06-01";

    private final String apiKey;
    private final String model;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Duration timeout;
    private int maxTokens = 1024;
    private double temperature = 0.7;

    public AnthropicGenerator(String apiKey, String model) {
        this(apiKey, model, Duration.ofSeconds(60));
    }

    public AnthropicGenerator(String apiKey, String model, Duration timeout) {
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
        return "anthropic." + model.replace("-", "_").replace(".", "_");
    }

    @Override
    public String getName() {
        return "Anthropic " + model;
    }

    @Override
    public String getProvider() {
        return "Anthropic";
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

            // Extract system message if present
            String systemMessage = null;
            ArrayNode messagesArray = requestBody.putArray("messages");

            for (Message message : messages) {
                if ("system".equals(message.role())) {
                    systemMessage = message.content();
                } else {
                    ObjectNode msgNode = messagesArray.addObject();
                    msgNode.put("role", message.role());
                    msgNode.put("content", message.content());
                }
            }

            if (systemMessage != null) {
                requestBody.put("system", systemMessage);
            }

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(API_URL))
                    .header("Content-Type", "application/json")
                    .header("x-api-key", apiKey)
                    .header("anthropic-version", API_VERSION)
                    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(requestBody)))
                    .timeout(timeout)
                    .build();

            log.debug("Sending request to Anthropic: {}", model);
            HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());

            Duration latency = Duration.ofNanos(System.nanoTime() - startTime);

            if (response.statusCode() != 200) {
                log.error("Anthropic API error: {} - {}", response.statusCode(), response.body());
                return GeneratorResponse.failure("Anthropic API error: " + response.statusCode());
            }

            JsonNode responseJson = objectMapper.readTree(response.body());

            // Extract content from response
            String content = responseJson
                    .path("content")
                    .get(0)
                    .path("text")
                    .asText();

            // Extract token usage
            GeneratorResponse.TokenUsage tokenUsage = null;
            JsonNode usage = responseJson.path("usage");
            if (!usage.isMissingNode()) {
                tokenUsage = GeneratorResponse.TokenUsage.of(
                        usage.path("input_tokens").asInt(),
                        usage.path("output_tokens").asInt()
                );
            }

            log.debug("Anthropic response received in {}ms", latency.toMillis());
            return GeneratorResponse.success(content, model, latency, tokenUsage);

        } catch (Exception e) {
            log.error("Anthropic API call failed", e);
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
     * Create a generator for Claude 3.5 Sonnet.
     */
    public static AnthropicGenerator claude35Sonnet(String apiKey) {
        return new AnthropicGenerator(apiKey, "claude-3-5-sonnet-20241022");
    }

    /**
     * Create a generator for Claude 3 Opus.
     */
    public static AnthropicGenerator claude3Opus(String apiKey) {
        return new AnthropicGenerator(apiKey, "claude-3-opus-20240229");
    }

    /**
     * Create a generator for Claude 3 Sonnet.
     */
    public static AnthropicGenerator claude3Sonnet(String apiKey) {
        return new AnthropicGenerator(apiKey, "claude-3-sonnet-20240229");
    }

    /**
     * Create a generator for Claude 3 Haiku.
     */
    public static AnthropicGenerator claude3Haiku(String apiKey) {
        return new AnthropicGenerator(apiKey, "claude-3-haiku-20240307");
    }
}
