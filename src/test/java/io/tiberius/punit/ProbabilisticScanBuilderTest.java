package io.tiberius.punit;

import io.tiberius.core.AttackCategory;
import io.tiberius.core.TiberiusScanner;
import io.tiberius.core.buff.Buff;
import io.tiberius.core.detector.CompositeDetector;
import io.tiberius.core.generator.MockGenerator;
import io.tiberius.core.probe.AbstractProbe;
import io.tiberius.core.probe.Probe;
import io.tiberius.core.probe.ProbeRegistry;
import org.javai.punit.api.Sampling;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for TiberiusScanner.ProbabilisticScanBuilder.
 */
class ProbabilisticScanBuilderTest {

    private TiberiusScanner scanner;
    private ProbeRegistry probeRegistry;

    @BeforeEach
    void setUp() {
        // Create empty registry without default probes
        probeRegistry = new ProbeRegistry() {
            // Override constructor behavior - don't register defaults
            {
                // Registry is empty at this point
            }
        };

        // Register only our test probes
        probeRegistry.register(new AbstractProbe(
                "punit-test-probe-001",
                "PUnit Test Probe 1",
                "Test description 1",
                AttackCategory.JAILBREAK,
                "Test prompt 1"
        ) {});

        probeRegistry.register(new AbstractProbe(
                "punit-test-probe-002",
                "PUnit Test Probe 2",
                "Test description 2",
                AttackCategory.PROMPT_INJECTION,
                "Test prompt 2"
        ) {
            @Override
            public int getSeverity() {
                return 4;
            }
        });

        scanner = TiberiusScanner.builder()
                .withProbeRegistry(probeRegistry)
                .withGenerator(MockGenerator.secure())
                .withDetector(CompositeDetector.defaultComposite())
                .withProbePatterns("punit-test-*")  // Only match our test probes
                .build();
    }

    @Test
    @DisplayName("multiTrialScan() returns builder")
    void multiTrialScanReturnsBuilder() {
        var builder = scanner.multiTrialScan();
        assertNotNull(builder);
    }

    @Test
    @DisplayName("Builder has fluent API")
    void builderHasFluentApi() {
        var builder = scanner.multiTrialScan()
                .samples(50)
                .minResistanceRate(0.90)
                .confidenceLevel(0.95)
                .maxLatency(Duration.ofSeconds(5))
                .withBuff(Buff.identity());

        assertNotNull(builder);
    }

    @Test
    @DisplayName("samples() validates minimum value")
    void samplesValidatesMinimum() {
        assertThrows(IllegalArgumentException.class, () ->
                scanner.multiTrialScan().samples(0)
        );

        assertThrows(IllegalArgumentException.class, () ->
                scanner.multiTrialScan().samples(-1)
        );
    }

    @Test
    @DisplayName("minResistanceRate() validates range")
    void minResistanceRateValidatesRange() {
        assertThrows(IllegalArgumentException.class, () ->
                scanner.multiTrialScan().minResistanceRate(-0.1)
        );

        assertThrows(IllegalArgumentException.class, () ->
                scanner.multiTrialScan().minResistanceRate(1.1)
        );
    }

    @Test
    @DisplayName("confidenceLevel() validates range")
    void confidenceLevelValidatesRange() {
        assertThrows(IllegalArgumentException.class, () ->
                scanner.multiTrialScan().confidenceLevel(-0.1)
        );

        assertThrows(IllegalArgumentException.class, () ->
                scanner.multiTrialScan().confidenceLevel(1.1)
        );
    }

    @Test
    @DisplayName("buildContract() creates valid SecurityContract")
    void buildContractCreatesValidContract() {
        SecurityContract contract = scanner.multiTrialScan()
                .samples(100)
                .minResistanceRate(0.95)
                .confidenceLevel(0.95)
                .buildContract();

        assertNotNull(contract);
        assertEquals(0.95, contract.getMinResistanceRate());
        assertEquals(0.95, contract.getConfidenceLevel());
        assertTrue(contract.id().startsWith("tiberius-"));
    }

    @Test
    @DisplayName("buildSampling() creates valid PUnit Sampling")
    void buildSamplingCreatesValidSampling() {
        Sampling<?, Probe, AttackOutcome> sampling = scanner.multiTrialScan()
                .samples(50)
                .buildSampling();

        assertNotNull(sampling);
        assertEquals(50, sampling.samples());
        // Should have probes matching our pattern (at least our 2 test probes)
        assertTrue(sampling.inputs().size() >= 2, "Should have at least 2 probes");
    }

    @Test
    @DisplayName("test() returns PUnit TestBuilder")
    void testReturnsPUnitTestBuilder() {
        var testBuilder = scanner.multiTrialScan()
                .samples(10)
                .test();

        assertNotNull(testBuilder);
    }

    @Test
    @DisplayName("Builder uses scanner's selected probes based on pattern")
    void builderUsesScannerProbes() {
        // Verify that the scanner's pattern filter is being used
        var sampling = scanner.multiTrialScan()
                .samples(50)
                .buildSampling();

        // Should have probes - the scanner uses pattern "punit-test-*"
        assertFalse(sampling.inputs().isEmpty(), "Should have at least one probe");

        // Verify that pattern matching worked - check if we got our registered probes
        var probeIds = sampling.inputs().stream()
                .map(Probe::getId)
                .toList();
        assertTrue(
                probeIds.stream().anyMatch(id -> id.startsWith("punit-test-")),
                "Should include probes matching punit-test-* pattern"
        );
    }

    @Test
    @DisplayName("Builder with maxLatency sets contract latency")
    void builderWithMaxLatencySetsContractLatency() {
        SecurityContract contract = scanner.multiTrialScan()
                .maxLatency(Duration.ofSeconds(3))
                .buildContract();

        assertTrue(contract.maxLatency().isPresent());
        assertEquals(Duration.ofSeconds(3), contract.maxLatency().get());
    }

    @Test
    @DisplayName("Builder without maxLatency has empty optional")
    void builderWithoutMaxLatencyHasEmptyOptional() {
        SecurityContract contract = scanner.multiTrialScan()
                .buildContract();

        assertTrue(contract.maxLatency().isEmpty());
    }
}
