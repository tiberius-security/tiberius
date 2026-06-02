package io.tiberius.core.probe;

import io.tiberius.core.AttackCategory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ProbeRegistry.
 */
class ProbeRegistryTest {

    private ProbeRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new ProbeRegistry();
    }

    @Test
    @DisplayName("Registry has default probes registered")
    void testDefaultProbesRegistered() {
        assertTrue(registry.size() > 0, "Registry should have probes");

        // Check specific probes exist
        assertTrue(registry.get("dan.11.0").isPresent(), "DAN 11.0 should exist");
        assertTrue(registry.get("encoding.base64").isPresent(), "Base64 encoding should exist");
        assertTrue(registry.get("extraction.system_prompt").isPresent(), "System prompt extraction should exist");
    }

    @Test
    @DisplayName("Get by ID returns correct probe")
    void testGetById() {
        var probe = registry.get("dan.11.0");

        assertTrue(probe.isPresent());
        assertEquals("dan.11.0", probe.get().getId());
        assertEquals(AttackCategory.JAILBREAK, probe.get().getCategory());
    }

    @Test
    @DisplayName("Get by category returns matching probes")
    void testGetByCategory() {
        List<Probe> jailbreaks = registry.getByCategory(AttackCategory.JAILBREAK);

        assertFalse(jailbreaks.isEmpty());
        jailbreaks.forEach(probe ->
                assertEquals(AttackCategory.JAILBREAK, probe.getCategory()));
    }

    @Test
    @DisplayName("Get by glob pattern works")
    void testGetByGlob() {
        List<Probe> danProbes = registry.getByGlob("dan.*");

        assertFalse(danProbes.isEmpty());
        danProbes.forEach(probe ->
                assertTrue(probe.getId().startsWith("dan."),
                        "Probe ID should start with 'dan.'"));
    }

    @Test
    @DisplayName("Get by multiple glob patterns works")
    void testGetByMultipleGlobs() {
        List<Probe> probes = registry.getByGlobs("dan.*", "persona.*");

        assertFalse(probes.isEmpty());
        probes.forEach(probe ->
                assertTrue(probe.getId().startsWith("dan.") || probe.getId().startsWith("persona."),
                        "Probe should match one of the patterns"));
    }

    @Test
    @DisplayName("Get by severity works")
    void testGetBySeverity() {
        List<Probe> highSeverity = registry.getBySeverityAtLeast(4);

        assertFalse(highSeverity.isEmpty());
        highSeverity.forEach(probe ->
                assertTrue(probe.getSeverity() >= 4,
                        "Probe severity should be >= 4"));
    }

    @Test
    @DisplayName("Get by tag works")
    void testGetByTag() {
        List<Probe> jailbreakTagged = registry.getByTag("jailbreak");

        assertFalse(jailbreakTagged.isEmpty());
        jailbreakTagged.forEach(probe ->
                assertTrue(probe.getTags().contains("jailbreak"),
                        "Probe should have 'jailbreak' tag"));
    }

    @Test
    @DisplayName("Custom predicate matching works")
    void testGetMatching() {
        List<Probe> highSeverityJailbreaks = registry.getMatching(probe ->
                probe.getCategory() == AttackCategory.JAILBREAK &&
                        probe.getSeverity() >= 4);

        assertFalse(highSeverityJailbreaks.isEmpty());
        highSeverityJailbreaks.forEach(probe -> {
            assertEquals(AttackCategory.JAILBREAK, probe.getCategory());
            assertTrue(probe.getSeverity() >= 4);
        });
    }

    @Test
    @DisplayName("Category summary is correct")
    void testCategorySummary() {
        var summary = registry.categorySummary();

        assertFalse(summary.isEmpty());
        assertTrue(summary.containsKey(AttackCategory.JAILBREAK));
        assertTrue(summary.get(AttackCategory.JAILBREAK) > 0);
    }

    @Test
    @DisplayName("Custom probe can be registered")
    void testCustomProbeRegistration() {
        Probe customProbe = new AbstractProbe(
                "custom.test",
                "Custom Test Probe",
                "A custom test probe",
                AttackCategory.JAILBREAK,
                "Test prompt"
        ) {};

        registry.register(customProbe);

        assertTrue(registry.get("custom.test").isPresent());
        assertEquals(customProbe, registry.get("custom.test").get());
    }

    @Test
    @DisplayName("Get all IDs returns unique set")
    void testGetIds() {
        var ids = registry.getIds();

        assertFalse(ids.isEmpty());
        assertEquals(registry.size(), ids.size(), "IDs count should match registry size");
    }
}
