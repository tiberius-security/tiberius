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
 * Generator implementation for local Ollama API.
 * Ollama runs locally on port 11434 by default.
 */
public final class OllamaGenerator implements Generator {

    private static final Logger log = LoggerFactory.getLogger(OllamaGenerator.class);
    private static final String DEFAULT_BASE_URL = "http://localhost:11434";

    private final String baseUrl;
    private final String model;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Duration timeout;
    private double temperature = 0.7;

    public OllamaGenerator(final String model) {
        this(DEFAULT_BASE_URL, model, Duration.ofSeconds(120));
    }

    public OllamaGenerator(final String baseUrl, final String model) {
        this(baseUrl, model, Duration.ofSeconds(120));
    }

    public OllamaGenerator(final String baseUrl, final String model, final Duration timeout) {
        this.baseUrl = baseUrl;
        this.model = model;
        this.timeout = timeout;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .build();
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public final String getId() {
        return "ollama." + model.replace(":", "_").replace("-", "_");
    }

    @Override
    public final String getName() {
        return "Ollama " + model;
    }

    @Override
    public final String getProvider() {
        return "Ollama";
    }

    @Override
    public final GeneratorResponse generate(final String prompt) {
        return generate(List.of(Message.user(prompt)));
    }

    @Override
    public final GeneratorResponse generate(final List<Message> messages) {
        final long startTime = System.nanoTime();

        try {
            final ObjectNode requestBody = buildRequestBody(messages);
            final HttpRequest request = buildHttpRequest(requestBody);

            log.debug("Sending request to Ollama: {}", model);
            final HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());

            final Duration latency = Duration.ofNanos(System.nanoTime() - startTime);

            if (response.statusCode() != 200) {
                log.error("Ollama API error: {} - {}", response.statusCode(), response.body());
                return GeneratorResponse.failure("Ollama API error: " + response.statusCode());
            }

            return parseResponse(response.body(), latency);

        } catch (final java.net.ConnectException e) {
            log.error("Cannot connect to Ollama at {}. Is Ollama running?", baseUrl);
            return GeneratorResponse.failure("Cannot connect to Ollama: " + e.getMessage());
        } catch (final Exception e) {
            log.error("Ollama API call failed", e);
            return GeneratorResponse.failure(e.getMessage());
        }
    }

    private ObjectNode buildRequestBody(final List<Message> messages) {
        final ObjectNode requestBody = objectMapper.createObjectNode();
        requestBody.put("model", model);
        requestBody.put("stream", false);

        final ObjectNode options = requestBody.putObject("options");
        options.put("temperature", temperature);

        final ArrayNode messagesArray = requestBody.putArray("messages");
        for (final Message message : messages) {
            final ObjectNode msgNode = messagesArray.addObject();
            msgNode.put("role", message.role());
            msgNode.put("content", message.content());
        }
        return requestBody;
    }

    private HttpRequest buildHttpRequest(final ObjectNode requestBody) throws Exception {
        final String url = baseUrl + "/api/chat";
        return HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(requestBody)))
                .timeout(timeout)
                .build();
    }

    private GeneratorResponse parseResponse(final String body, final Duration latency) throws Exception {
        final JsonNode responseJson = objectMapper.readTree(body);
        final String content = responseJson.path("message").path("content").asText();

        GeneratorResponse.TokenUsage tokenUsage = null;
        if (responseJson.has("prompt_eval_count") && responseJson.has("eval_count")) {
            tokenUsage = GeneratorResponse.TokenUsage.of(
                    responseJson.path("prompt_eval_count").asInt(),
                    responseJson.path("eval_count").asInt()
            );
        }

        log.debug("Ollama response received in {}ms", latency.toMillis());
        return GeneratorResponse.success(content, model, latency, tokenUsage);
    }

    @Override
    public final void configure(final Map<String, Object> options) {
        if (options.containsKey("temperature")) {
            this.temperature = ((Number) options.get("temperature")).doubleValue();
        }
    }

    @Override
    public final boolean isAvailable() {
        try {
            final HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/api/tags"))
                    .GET()
                    .timeout(Duration.ofSeconds(5))
                    .build();

            final HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());

            return response.statusCode() == 200;
        } catch (final Exception e) {
            return false;
        }
    }

    public final List<String> listModels() {
        try {
            final HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/api/tags"))
                    .GET()
                    .timeout(Duration.ofSeconds(10))
                    .build();

            final HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                final JsonNode root = objectMapper.readTree(response.body());
                return java.util.stream.StreamSupport.stream(
                                root.path("models").spliterator(), false)
                        .map(node -> node.path("name").asText())
                        .toList();
            }
        } catch (final Exception e) {
            log.warn("Failed to list Ollama models: {}", e.getMessage());
        }
        return List.of();
    }

    public static OllamaGenerator llama3() {
        return new OllamaGenerator("llama3.2");
    }

    public static OllamaGenerator llama3_1() {
        return new OllamaGenerator("llama3.1");
    }

    public static OllamaGenerator mistral() {
        return new OllamaGenerator("mistral");
    }

    public static OllamaGenerator codellama() {
        return new OllamaGenerator("codellama");
    }

    public static OllamaGenerator model(final String modelName) {
        return new OllamaGenerator(modelName);
    }
}
