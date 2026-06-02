package io.tiberius.examples;

import io.tiberius.core.AttackCategory;
import io.tiberius.core.TiberiusScanner;
import io.tiberius.core.buff.EncodingBuffs;
import io.tiberius.core.buff.StyleBuffs;
import io.tiberius.core.detector.CompositeDetector;
import io.tiberius.core.generator.MockGenerator;
import io.tiberius.core.probe.Probe;
import io.tiberius.core.probe.ProbeRegistry;
import io.tiberius.core.result.ScanResult;
import io.tiberius.junit.ProbeSource;
import io.tiberius.junit.TiberiusExtension;
import io.tiberius.spring.PromptInjectionTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Example of parameterized tests that run individual probes.
 */
@ExtendWith(TiberiusExtension.class)
@PromptInjectionTest(description = "Parameterized probe testing")
@DisplayName("Parameterized Probe Tests")
class ParameterizedProbeTest {

    private final TiberiusScanner scanner = TiberiusScanner.builder()
            .withGenerator(MockGenerator.secure())
            .withDetector(CompositeDetector.defaultComposite())
            .build();

    @ParameterizedTest(name = "Jailbreak probe: {0}")
    @ProbeSource(categories = AttackCategory.JAILBREAK)
    @DisplayName("Test individual jailbreak probes")
    void testJailbreakProbes(Probe probe) {
        ScanResult result = scanner.runProbe(probe);

        assertFalse(result.attackSucceeded(),
                () -> "Jailbreak probe should be blocked: " + probe.getId() +
                        "\nResponse: " + result.response());
    }

    @ParameterizedTest(name = "Encoding probe: {0}")
    @ProbeSource(categories = AttackCategory.ENCODING)
    @DisplayName("Test individual encoding probes")
    void testEncodingProbes(Probe probe) {
        ScanResult result = scanner.runProbe(probe);

        assertFalse(result.attackSucceeded(),
                () -> "Encoding probe should be blocked: " + probe.getId());
    }

    @ParameterizedTest(name = "Data extraction probe: {0}")
    @ProbeSource(categories = AttackCategory.DATA_EXTRACTION)
    @DisplayName("Test data extraction probes")
    void testDataExtractionProbes(Probe probe) {
        ScanResult result = scanner.runProbe(probe);

        assertFalse(result.attackSucceeded(),
                () -> "Data extraction should be blocked: " + probe.getId());
    }

    @ParameterizedTest(name = "High severity probe: {0}")
    @ProbeSource(minSeverity = 4)
    @DisplayName("Test high severity probes")
    void testHighSeverityProbes(Probe probe) {
        ScanResult result = scanner.runProbe(probe);

        assertFalse(result.attackSucceeded(),
                () -> "High severity probe (severity " + probe.getSeverity() +
                        ") should be blocked: " + probe.getId());
    }

    @ParameterizedTest(name = "Probe with Base64 buff: {0}")
    @ProbeSource(patterns = "dan.*", limit = 3)
    @DisplayName("Test probes with Base64 encoding buff")
    void testProbesWithBase64Buff(Probe probe) {
        ScanResult result = scanner.runProbe(probe, EncodingBuffs.BASE64);

        assertFalse(result.attackSucceeded(),
                () -> "Base64-encoded probe should be blocked: " + probe.getId());
        assertEquals("Base64", result.buffName());
    }

    @ParameterizedTest(name = "Probe with hypothetical framing: {0}")
    @ProbeSource(patterns = "injection.*", limit = 3)
    @DisplayName("Test probes with hypothetical framing buff")
    void testProbesWithHypotheticalBuff(Probe probe) {
        ScanResult result = scanner.runProbe(probe, StyleBuffs.HYPOTHETICAL);

        assertFalse(result.attackSucceeded(),
                () -> "Hypothetically-framed probe should be blocked: " + probe.getId());
    }
}
