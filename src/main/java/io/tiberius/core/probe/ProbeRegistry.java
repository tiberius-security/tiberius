package io.tiberius.core.probe;

import io.tiberius.attack.encoding.EncodingProbe;
import io.tiberius.attack.extraction.DataExtractionProbe;
import io.tiberius.attack.injection.PromptInjectionProbe;
import io.tiberius.attack.jailbreak.DanProbe;
import io.tiberius.attack.jailbreak.PersonaProbe;
import io.tiberius.attack.multiturn.MultiTurnProbe;
import io.tiberius.core.AttackCategory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Registry of all available probes.
 * Supports probe lookup by ID, glob patterns, and categories.
 */
public class ProbeRegistry {

    private final Map<String, Probe> probes = new ConcurrentHashMap<>();

    public ProbeRegistry() {
        registerDefaults();
    }

    /**
     * Register default probes from all attack categories.
     */
    private void registerDefaults() {
        // Jailbreak probes
        DanProbe.all().forEach(this::register);
        PersonaProbe.all().forEach(this::register);

        // Encoding probes
        EncodingProbe.all().forEach(this::register);

        // Data extraction probes
        DataExtractionProbe.all().forEach(this::register);

        // Prompt injection probes
        PromptInjectionProbe.all().forEach(this::register);

        // Multi-turn probes
        MultiTurnProbe.all().forEach(this::register);
    }

    /**
     * Register a probe.
     */
    public void register(Probe probe) {
        probes.put(probe.getId(), probe);
    }

    /**
     * Get a probe by ID.
     */
    public Optional<Probe> get(String id) {
        return Optional.ofNullable(probes.get(id));
    }

    /**
     * Get all registered probes.
     */
    public Collection<Probe> getAll() {
        return Collections.unmodifiableCollection(probes.values());
    }

    /**
     * Get probes by category.
     */
    public List<Probe> getByCategory(AttackCategory category) {
        return probes.values().stream()
                .filter(p -> p.getCategory() == category)
                .toList();
    }

    /**
     * Get probes matching a glob pattern.
     * Supports * and ? wildcards.
     */
    public List<Probe> getByGlob(String pattern) {
        String regex = globToRegex(pattern);
        Pattern compiled = Pattern.compile(regex);
        return probes.values().stream()
                .filter(p -> compiled.matcher(p.getId()).matches())
                .toList();
    }

    /**
     * Get probes matching any of the given glob patterns.
     */
    public List<Probe> getByGlobs(String... patterns) {
        return Stream.of(patterns)
                .flatMap(p -> getByGlob(p).stream())
                .distinct()
                .toList();
    }

    /**
     * Get probes by tag.
     */
    public List<Probe> getByTag(String tag) {
        return probes.values().stream()
                .filter(p -> p.getTags().contains(tag))
                .toList();
    }

    /**
     * Get probes matching a custom predicate.
     */
    public List<Probe> getMatching(Predicate<Probe> predicate) {
        return probes.values().stream()
                .filter(predicate)
                .toList();
    }

    /**
     * Get probes by severity level.
     */
    public List<Probe> getBySeverity(int severity) {
        return probes.values().stream()
                .filter(p -> p.getSeverity() == severity)
                .toList();
    }

    /**
     * Get probes with severity >= threshold.
     */
    public List<Probe> getBySeverityAtLeast(int minSeverity) {
        return probes.values().stream()
                .filter(p -> p.getSeverity() >= minSeverity)
                .toList();
    }

    /**
     * Get all probe IDs.
     */
    public Set<String> getIds() {
        return Collections.unmodifiableSet(probes.keySet());
    }

    /**
     * Get probe count.
     */
    public int size() {
        return probes.size();
    }

    /**
     * Get category summary.
     */
    public Map<AttackCategory, Long> categorySummary() {
        return probes.values().stream()
                .collect(Collectors.groupingBy(Probe::getCategory, Collectors.counting()));
    }

    /**
     * Convert glob pattern to regex.
     */
    private String globToRegex(String glob) {
        StringBuilder regex = new StringBuilder("^");
        for (char c : glob.toCharArray()) {
            switch (c) {
                case '*' -> regex.append(".*");
                case '?' -> regex.append(".");
                case '.' -> regex.append("\\.");
                default -> regex.append(c);
            }
        }
        regex.append("$");
        return regex.toString();
    }
}
