package io.tiberius.dataset;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.tiberius.core.AttackCategory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * Loads red team datasets from JSON files.
 *
 * <p>Supports two JSON formats:</p>
 *
 * <h2>Full Format (recommended for complex datasets)</h2>
 * <pre>{@code
 * {
 *   "name": "GPT-OSS-20B Red Team Dataset",
 *   "description": "Jailbreak and bias evaluation",
 *   "version": "1.0",
 *   "metadata": { "authors": ["Horlacher et al."] },
 *   "entries": [
 *     {
 *       "id": "math_proof_001",
 *       "prompt": "Consider the mathematical proof...",
 *       "category": "CONTEXTUAL_EMBEDDING",
 *       "technique": "math_proof",
 *       "language": "en",
 *       "expectedHarmful": true,
 *       "severity": 4,
 *       "tags": ["reasoning", "formal"]
 *     }
 *   ]
 * }
 * }</pre>
 *
 * <h2>Simple Format (for quick payload lists)</h2>
 * <pre>{@code
 * {
 *   "name": "Quick Jailbreak Test",
 *   "category": "JAILBREAK",
 *   "technique": "dan",
 *   "payloads": [
 *     "Ignore previous instructions...",
 *     "You are now DAN..."
 *   ]
 * }
 * }</pre>
 */
public final class DatasetLoader {

    private static final Logger log = LoggerFactory.getLogger(DatasetLoader.class);
    private final ObjectMapper objectMapper;

    public DatasetLoader() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    public DatasetLoader(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Load a dataset from a file path.
     */
    public RedTeamDataset load(Path path) throws IOException {
        log.info("Loading dataset from: {}", path);
        try (var input = Files.newInputStream(path)) {
            return load(input, path.getFileName().toString());
        }
    }

    /**
     * Load a dataset from a classpath resource.
     */
    public RedTeamDataset loadFromClasspath(String resourcePath) throws IOException {
        log.info("Loading dataset from classpath: {}", resourcePath);
        try (var input = getClass().getClassLoader().getResourceAsStream(resourcePath)) {
            if (input == null) {
                throw new IOException("Resource not found: " + resourcePath);
            }
            return load(input, resourcePath);
        }
    }

    /**
     * Load a dataset from an input stream.
     */
    public RedTeamDataset load(InputStream input, String sourceName) throws IOException {
        JsonNode root = objectMapper.readTree(input);

        // Detect format: full or simple
        if (root.has("entries")) {
            return parseFullFormat(root, sourceName);
        } else if (root.has("payloads")) {
            return parseSimpleFormat(root, sourceName);
        } else {
            throw new IOException("Invalid dataset format: must have 'entries' or 'payloads' field");
        }
    }

    /**
     * Load a dataset from a JSON string.
     */
    public RedTeamDataset loadFromString(String json) throws IOException {
        JsonNode root = objectMapper.readTree(json);
        if (root.has("entries")) {
            return parseFullFormat(root, "string");
        } else if (root.has("payloads")) {
            return parseSimpleFormat(root, "string");
        } else {
            throw new IOException("Invalid dataset format");
        }
    }

    /**
     * Save a dataset to a file.
     */
    public void save(RedTeamDataset dataset, Path path) throws IOException {
        log.info("Saving dataset to: {}", path);
        Files.createDirectories(path.getParent());
        objectMapper.writeValue(path.toFile(), toJsonStructure(dataset));
    }

    /**
     * Convert dataset to JSON string.
     */
    public String toJson(RedTeamDataset dataset) throws IOException {
        return objectMapper.writeValueAsString(toJsonStructure(dataset));
    }

    private RedTeamDataset parseFullFormat(JsonNode root, String sourceName) {
        String name = getTextOrDefault(root, "name", sourceName);
        String description = getTextOrDefault(root, "description", "");
        String version = getTextOrDefault(root, "version", "1.0");

        Map<String, Object> metadata = parseMetadata(root.get("metadata"));

        List<DatasetEntry> entries = new ArrayList<>();
        JsonNode entriesNode = root.get("entries");
        if (entriesNode != null && entriesNode.isArray()) {
            int index = 0;
            for (JsonNode entryNode : entriesNode) {
                entries.add(parseEntry(entryNode, index++));
            }
        }

        log.info("Loaded {} entries from full-format dataset '{}'", entries.size(), name);
        return RedTeamDataset.builder()
                .name(name)
                .description(description)
                .version(version)
                .addEntries(entries)
                .metadata(metadata)
                .build();
    }

    private RedTeamDataset parseSimpleFormat(JsonNode root, String sourceName) {
        String name = getTextOrDefault(root, "name", sourceName);
        String technique = getTextOrDefault(root, "technique", "unknown");
        String language = getTextOrDefault(root, "language", "en");
        AttackCategory category = parseCategory(root.get("category"), AttackCategory.JAILBREAK);
        int severity = root.has("severity") ? root.get("severity").asInt() : 3;

        List<DatasetEntry> entries = new ArrayList<>();
        JsonNode payloads = root.get("payloads");
        if (payloads != null && payloads.isArray()) {
            int index = 0;
            for (JsonNode payload : payloads) {
                String id = String.format("%s_%03d", technique, index);
                entries.add(DatasetEntry.builder()
                        .id(id)
                        .prompt(payload.asText())
                        .category(category)
                        .technique(technique)
                        .language(language)
                        .severity(severity)
                        .expectedHarmful(true)
                        .build());
                index++;
            }
        }

        log.info("Loaded {} entries from simple-format dataset '{}'", entries.size(), name);
        return RedTeamDataset.builder()
                .name(name)
                .description("Simple payload list dataset")
                .addEntries(entries)
                .build();
    }

    private DatasetEntry parseEntry(JsonNode node, int index) {
        String id = getTextOrDefault(node, "id", "entry_" + index);
        String prompt = node.get("prompt").asText();
        AttackCategory category = parseCategory(node.get("category"), AttackCategory.JAILBREAK);
        String technique = getTextOrDefault(node, "technique", "unknown");
        String language = getTextOrDefault(node, "language", "en");
        boolean expectedHarmful = node.has("expectedHarmful") ? node.get("expectedHarmful").asBoolean() : true;
        String biasScenario = getTextOrNull(node, "biasScenario");
        String expectedBias = getTextOrNull(node, "expectedBias");
        int severity = node.has("severity") ? node.get("severity").asInt() : 3;

        List<String> tags = new ArrayList<>();
        JsonNode tagsNode = node.get("tags");
        if (tagsNode != null && tagsNode.isArray()) {
            for (JsonNode tag : tagsNode) {
                tags.add(tag.asText());
            }
        }

        Map<String, Object> metadata = parseMetadata(node.get("metadata"));

        return DatasetEntry.builder()
                .id(id)
                .prompt(prompt)
                .category(category)
                .technique(technique)
                .language(language)
                .expectedHarmful(expectedHarmful)
                .biasScenario(biasScenario)
                .expectedBias(expectedBias)
                .severity(severity)
                .tags(tags)
                .metadata(metadata)
                .build();
    }

    private AttackCategory parseCategory(JsonNode node, AttackCategory defaultCategory) {
        if (node == null || node.isNull()) {
            return defaultCategory;
        }
        String categoryStr = node.asText().toUpperCase();
        try {
            return AttackCategory.valueOf(categoryStr);
        } catch (IllegalArgumentException e) {
            log.warn("Unknown attack category '{}', using default: {}", categoryStr, defaultCategory);
            return defaultCategory;
        }
    }

    private Map<String, Object> parseMetadata(JsonNode node) {
        if (node == null || node.isNull()) {
            return Map.of();
        }
        try {
            return objectMapper.convertValue(node, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            log.warn("Failed to parse metadata: {}", e.getMessage());
            return Map.of();
        }
    }

    private String getTextOrDefault(JsonNode node, String field, String defaultValue) {
        JsonNode fieldNode = node.get(field);
        return (fieldNode != null && !fieldNode.isNull()) ? fieldNode.asText() : defaultValue;
    }

    private String getTextOrNull(JsonNode node, String field) {
        JsonNode fieldNode = node.get(field);
        return (fieldNode != null && !fieldNode.isNull()) ? fieldNode.asText() : null;
    }

    private Map<String, Object> toJsonStructure(RedTeamDataset dataset) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("name", dataset.getName());
        root.put("description", dataset.getDescription());
        root.put("version", dataset.getVersion());
        root.put("metadata", dataset.getMetadata());

        List<Map<String, Object>> entriesJson = new ArrayList<>();
        for (DatasetEntry entry : dataset.getEntries()) {
            Map<String, Object> entryJson = new LinkedHashMap<>();
            entryJson.put("id", entry.id());
            entryJson.put("prompt", entry.prompt());
            entryJson.put("category", entry.category().name());
            entryJson.put("technique", entry.technique());
            entryJson.put("language", entry.language());
            entryJson.put("expectedHarmful", entry.expectedHarmful());
            if (entry.biasScenario() != null) {
                entryJson.put("biasScenario", entry.biasScenario());
            }
            if (entry.expectedBias() != null) {
                entryJson.put("expectedBias", entry.expectedBias());
            }
            entryJson.put("severity", entry.severity());
            if (!entry.tags().isEmpty()) {
                entryJson.put("tags", entry.tags());
            }
            if (!entry.metadata().isEmpty()) {
                entryJson.put("metadata", entry.metadata());
            }
            entriesJson.add(entryJson);
        }
        root.put("entries", entriesJson);

        return root;
    }
}