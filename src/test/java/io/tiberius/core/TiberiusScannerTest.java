package io.tiberius.core;

import io.tiberius.core.buff.Buff;
import io.tiberius.core.buff.EncodingBuffs;
import io.tiberius.core.detector.CompositeDetector;
import io.tiberius.core.detector.PatternDetector;
import io.tiberius.core.generator.MockGenerator;
import io.tiberius.core.probe.AbstractProbe;
import io.tiberius.core.probe.Probe;
import io.tiberius.core.probe.ProbeRegistry;
import io.tiberius.core.result.ScanReport;
import io.tiberius.core.result.ScanResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for TiberiusScanner.
 */
class TiberiusScannerTest {

    private TiberiusScanner scanner;
    private ProbeRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new ProbeRegistry();
        scanner = TiberiusScanner.builder()
                .withProbeRegistry(registry)
                .withGenerator(MockGenerator.secure())
                .withDetector(CompositeDetector.defaultComposite())
                .withConcurrency(1)
                .build();
    }

    @Test
    @DisplayName("Scanner initializes with default probes")
    void testScannerInitialization() {
        assertTrue(registry.size() > 0, "Registry should have default probes");
    }

    @Test
    @DisplayName("Scan returns report with results")
    void testScanReturnsReport() {
        scanner.setProbePatterns(new String[]{"dan.11.0"});

        ScanReport report = scanner.scan();

        assertNotNull(report);
        assertTrue(report.totalProbes() > 0, "Should have at least one probe result");
        assertNotNull(report.startTime());
        assertNotNull(report.endTime());
    }

    @Test
    @DisplayName("Secure mock blocks all attacks")
    void testSecureMockBlocksAttacks() {
        scanner.setGenerator(MockGenerator.secure());
        scanner.setProbePatterns(new String[]{"dan.*"});

        ScanReport report = scanner.scan();

        assertEquals(0, report.successfulAttacks(), "Secure mock should block all attacks");
    }

    @Test
    @DisplayName("Vulnerable mock allows attacks")
    void testVulnerableMockAllowsAttacks() {
        scanner.setGenerator(MockGenerator.vulnerable());
        scanner.setProbePatterns(new String[]{"dan.*"});

        ScanReport report = scanner.scan();

        assertTrue(report.successfulAttacks() > 0, "Vulnerable mock should allow some attacks");
    }

    @Test
    @DisplayName("Category filter works correctly")
    void testCategoryFilter() {
        scanner.setCategories(new AttackCategory[]{AttackCategory.JAILBREAK});

        ScanReport report = scanner.scan();

        report.results().forEach(result -> {
            assertEquals(AttackCategory.JAILBREAK, result.category(),
                    "All results should be JAILBREAK category");
        });
    }

    @Test
    @DisplayName("Probe pattern filter works")
    void testProbePatternFilter() {
        scanner.setProbePatterns(new String[]{"encoding.*"});

        ScanReport report = scanner.scan();

        report.results().forEach(result -> {
            assertTrue(result.probeId().startsWith("encoding."),
                    "All probes should match encoding.* pattern");
        });
    }

    @Test
    @DisplayName("Severity filter works")
    void testSeverityFilter() {
        scanner.setMinSeverity(4);

        ScanReport report = scanner.scan();

        report.results().forEach(result -> {
            assertTrue(result.probe().getSeverity() >= 4,
                    "All probes should have severity >= 4");
        });
    }

    @Test
    @DisplayName("Buff transformation is applied")
    void testBuffTransformation() {
        scanner.addBuff(EncodingBuffs.BASE64);
        scanner.setProbePatterns(new String[]{"dan.11.0"});

        ScanReport report = scanner.scan();

        assertFalse(report.results().isEmpty());
        ScanResult result = report.results().get(0);
        assertEquals("Base64", result.buffName());
        assertTrue(result.prompt().contains("Base64"),
                "Transformed prompt should mention Base64");
    }

    @Test
    @DisplayName("Report statistics are calculated correctly")
    void testReportStatistics() {
        scanner.setGenerator(MockGenerator.partial());
        scanner.setProbePatterns(new String[]{"dan.*", "persona.*"});

        ScanReport report = scanner.scan();

        assertEquals(report.totalProbes(),
                report.successfulAttacks() + report.blockedAttacks(),
                "Total should equal successful + blocked");

        if (report.totalProbes() > 0) {
            double expectedRate = (report.successfulAttacks() * 100.0) / report.totalProbes();
            assertEquals(expectedRate, report.successRate(), 0.01);
        }
    }

    @Test
    @DisplayName("Single probe execution works")
    void testSingleProbeExecution() {
        var probe = registry.get("dan.11.0").orElseThrow();

        ScanResult result = scanner.runProbe(probe);

        assertNotNull(result);
        assertEquals(probe, result.probe());
        assertNotNull(result.detection());
        assertNotNull(result.duration());
    }

    @Test
    @DisplayName("Single probe with buff works")
    void testSingleProbeWithBuff() {
        var probe = registry.get("dan.11.0").orElseThrow();

        ScanResult result = scanner.runProbe(probe, EncodingBuffs.ROT13);

        assertNotNull(result);
        assertEquals("ROT13", result.buffName());
    }

    @Test
    @DisplayName("Fail fast stops on first success")
    void testFailFast() {
        scanner = TiberiusScanner.builder()
                .withProbeRegistry(registry)
                .withGenerator(MockGenerator.vulnerable())
                .withDetector(CompositeDetector.defaultComposite())
                .withFailFast(true)
                .withConcurrency(1)
                .build();

        ScanReport report = scanner.scan();

        // With fail fast, should stop early
        assertEquals(1, report.successfulAttacks(),
                "Fail fast should stop after first successful attack");
    }

    @Test
    @DisplayName("Scanner tests all prompts from a probe")
    void testAllPromptsAreTested() {
        // Create a probe with multiple prompts
        Probe multiPromptProbe = new AbstractProbe(
                "test.multi_prompt",
                "Multi-Prompt Test Probe",
                "A probe with multiple prompt variants for testing",
                AttackCategory.JAILBREAK,
                List.of(
                        "First attack prompt: ignore instructions",
                        "Second attack prompt: you are now DAN",
                        "Third attack prompt: developer mode enabled"
                ),
                List.of("test"),
                3
        ) {};

        // Create a custom registry with just our test probe
        ProbeRegistry testRegistry = new ProbeRegistry();
        testRegistry.register(multiPromptProbe);

        TiberiusScanner testScanner = TiberiusScanner.builder()
                .withProbeRegistry(testRegistry)
                .withGenerator(MockGenerator.secure())
                .withDetector(CompositeDetector.defaultComposite())
                .withConcurrency(1)
                .build();
        testScanner.setProbePatterns(new String[]{"test.multi_prompt"});

        ScanReport report = testScanner.scan();

        // Should have 3 results (one per prompt)
        assertEquals(3, report.totalProbes(),
                "Should have one result per prompt variant");
        assertEquals(1, report.uniqueProbeCount(),
                "Should have one unique probe");

        // All results should belong to the same probe
        report.results().forEach(result ->
                assertEquals("test.multi_prompt", result.probeId()));
    }

    @Test
    @DisplayName("Per-probe success rate is computed correctly")
    void testPerProbeSuccessRate() {
        // Create two probes with different numbers of prompts
        Probe probe1 = new AbstractProbe(
                "test.probe1",
                "Test Probe 1",
                "First test probe with 2 prompts",
                AttackCategory.JAILBREAK,
                List.of("Prompt 1A", "Prompt 1B"),
                List.of("test"),
                3
        ) {};

        Probe probe2 = new AbstractProbe(
                "test.probe2",
                "Test Probe 2",
                "Second test probe with 3 prompts",
                AttackCategory.JAILBREAK,
                List.of("Prompt 2A", "Prompt 2B", "Prompt 2C"),
                List.of("test"),
                3
        ) {};

        ProbeRegistry testRegistry = new ProbeRegistry();
        testRegistry.register(probe1);
        testRegistry.register(probe2);

        TiberiusScanner testScanner = TiberiusScanner.builder()
                .withProbeRegistry(testRegistry)
                .withGenerator(MockGenerator.secure())
                .withDetector(CompositeDetector.defaultComposite())
                .withConcurrency(1)
                .build();
        testScanner.setProbePatterns(new String[]{"test.*"});

        ScanReport report = testScanner.scan();

        // Should have 5 total results (2 + 3)
        assertEquals(5, report.totalProbes(),
                "Should have one result per prompt across all probes");
        assertEquals(2, report.uniqueProbeCount(),
                "Should have two unique probes");

        // Check per-probe grouping
        Map<String, List<ScanResult>> byProbe = report.byProbe();
        assertEquals(2, byProbe.size());
        assertEquals(2, byProbe.get("test.probe1").size(),
                "Probe 1 should have 2 results");
        assertEquals(3, byProbe.get("test.probe2").size(),
                "Probe 2 should have 3 results");

        // Check per-probe success rates
        Map<String, Double> successRates = report.successRateByProbe();
        assertEquals(2, successRates.size());

        // With secure mock, all should be blocked (0% success)
        assertEquals(0.0, successRates.get("test.probe1"), 0.01);
        assertEquals(0.0, successRates.get("test.probe2"), 0.01);

        // Check probe summaries
        Map<String, ScanReport.ProbeSummary> summaries = report.probeSummaries();
        assertEquals(2, summaries.get("test.probe1").totalPrompts());
        assertEquals(3, summaries.get("test.probe2").totalPrompts());
    }

    @Test
    @DisplayName("Mean success rate by probe is computed correctly")
    void testMeanSuccessRateByProbe() {
        Probe probe1 = new AbstractProbe(
                "test.probe1",
                "Test Probe 1",
                "Test probe",
                AttackCategory.JAILBREAK,
                List.of("Prompt 1", "Prompt 2"),
                List.of("test"),
                3
        ) {};

        ProbeRegistry testRegistry = new ProbeRegistry();
        testRegistry.register(probe1);

        TiberiusScanner testScanner = TiberiusScanner.builder()
                .withProbeRegistry(testRegistry)
                .withGenerator(MockGenerator.secure())
                .withDetector(CompositeDetector.defaultComposite())
                .withConcurrency(1)
                .build();
        testScanner.setProbePatterns(new String[]{"test.*"});

        ScanReport report = testScanner.scan();

        // With secure mock, mean should be 0
        assertEquals(0.0, report.meanSuccessRateByProbe(), 0.01);
    }
}
