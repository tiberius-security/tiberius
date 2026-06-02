package io.tiberius.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for Tiberius prompt injection testing.
 */
@ConfigurationProperties(prefix = "tiberius")
public class TiberiusProperties {

    /**
     * Enable Tiberius testing.
     */
    private boolean enabled = true;

    /**
     * Generator to use (e.g., "ollama", "mock").
     */
    private String generator;

    /**
     * Ollama base URL (default: http://localhost:11434).
     */
    private String ollamaBaseUrl = "http://localhost:11434";

    /**
     * Model to use (e.g., "llama3.2:1b", "mistral").
     */
    private String model = "llama3.2:1b";

    /**
     * Concurrency level for parallel scanning.
     */
    private int concurrency = 10;

    /**
     * Minimum severity level to test.
     */
    private int minSeverity = 1;

    /**
     * Maximum acceptable attack success rate (percentage).
     */
    private double maxSuccessRate = 0.0;

    /**
     * Whether to fail fast on first successful attack.
     */
    private boolean failFast = false;

    /**
     * Probe patterns to include.
     */
    private List<String> probePatterns = new ArrayList<>();

    /**
     * Probe patterns to exclude.
     */
    private List<String> excludePatterns = new ArrayList<>();

    /**
     * Categories to test.
     */
    private List<String> categories = new ArrayList<>();

    /**
     * Buffs to apply.
     */
    private List<String> buffs = new ArrayList<>();

    // Getters and setters
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getGenerator() {
        return generator;
    }

    public void setGenerator(String generator) {
        this.generator = generator;
    }

    public String getOllamaBaseUrl() {
        return ollamaBaseUrl;
    }

    public void setOllamaBaseUrl(String ollamaBaseUrl) {
        this.ollamaBaseUrl = ollamaBaseUrl;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public int getConcurrency() {
        return concurrency;
    }

    public void setConcurrency(int concurrency) {
        this.concurrency = concurrency;
    }

    public int getMinSeverity() {
        return minSeverity;
    }

    public void setMinSeverity(int minSeverity) {
        this.minSeverity = minSeverity;
    }

    public double getMaxSuccessRate() {
        return maxSuccessRate;
    }

    public void setMaxSuccessRate(double maxSuccessRate) {
        this.maxSuccessRate = maxSuccessRate;
    }

    public boolean isFailFast() {
        return failFast;
    }

    public void setFailFast(boolean failFast) {
        this.failFast = failFast;
    }

    public List<String> getProbePatterns() {
        return probePatterns;
    }

    public void setProbePatterns(List<String> probePatterns) {
        this.probePatterns = probePatterns;
    }

    public List<String> getExcludePatterns() {
        return excludePatterns;
    }

    public void setExcludePatterns(List<String> excludePatterns) {
        this.excludePatterns = excludePatterns;
    }

    public List<String> getCategories() {
        return categories;
    }

    public void setCategories(List<String> categories) {
        this.categories = categories;
    }

    public List<String> getBuffs() {
        return buffs;
    }

    public void setBuffs(List<String> buffs) {
        this.buffs = buffs;
    }
}
