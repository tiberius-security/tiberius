package io.tiberius.punit;

import io.tiberius.core.AttackCategory;
import io.tiberius.core.detector.DetectionResult;
import io.tiberius.core.probe.AbstractProbe;
import io.tiberius.core.probe.Probe;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for AttackOutcome record.
 */
class AttackOutcomeTest {

    private Probe testProbe;

    @BeforeEach
    void setUp() {
        testProbe = new AbstractProbe(
                "test-probe-001",
                "Test Probe",
                "A test probe",
                AttackCategory.JAILBREAK,
                "Test prompt"
        ) {
            @Override
            public int getSeverity() {
                return 4;
            }
        };
    }

    @Test
    @DisplayName("AttackOutcome.of() creates outcome from detection result")
    void ofCreatesOutcomeFromDetection() {
        DetectionResult detection = DetectionResult.attackSucceeded(0.95, "Attack detected");
        Duration latency = Duration.ofMillis(150);

        AttackOutcome outcome = AttackOutcome.of(
                testProbe,
                detection,
                "LLM response",
                latency
        );

        assertEquals("test-probe-001", outcome.probeId());
        assertEquals("JAILBREAK", outcome.category());
        assertEquals(4, outcome.severity());
        assertTrue(outcome.attackSucceeded());
        assertEquals(0.95, outcome.consensusScore());
        assertEquals("LLM response", outcome.response());
        assertEquals(latency, outcome.latency());
        assertNull(outcome.error());
    }

    @Test
    @DisplayName("AttackOutcome.of() handles blocked attack")
    void ofHandlesBlockedAttack() {
        DetectionResult detection = DetectionResult.attackBlocked(0.90, "Attack blocked");

        AttackOutcome outcome = AttackOutcome.of(
                testProbe,
                detection,
                "Safe response",
                Duration.ofMillis(100)
        );

        assertFalse(outcome.attackSucceeded());
        assertTrue(outcome.attackBlocked());
        assertTrue(outcome.executedSuccessfully());
    }

    @Test
    @DisplayName("AttackOutcome.error() creates error outcome")
    void errorCreatesErrorOutcome() {
        Duration latency = Duration.ofMillis(50);

        AttackOutcome outcome = AttackOutcome.error(
                testProbe,
                "Connection timeout",
                latency
        );

        assertEquals("test-probe-001", outcome.probeId());
        assertEquals("JAILBREAK", outcome.category());
        assertEquals(4, outcome.severity());
        assertFalse(outcome.attackSucceeded());
        assertEquals(0.0, outcome.consensusScore());
        assertNull(outcome.response());
        assertEquals(latency, outcome.latency());
        assertEquals("Connection timeout", outcome.error());
    }

    @Test
    @DisplayName("executedSuccessfully() returns true when no error")
    void executedSuccessfullyTrueWhenNoError() {
        AttackOutcome successOutcome = AttackOutcome.of(
                testProbe,
                DetectionResult.attackBlocked(0.9, "Blocked"),
                "Response",
                Duration.ofMillis(100)
        );

        assertTrue(successOutcome.executedSuccessfully());
    }

    @Test
    @DisplayName("executedSuccessfully() returns false when error present")
    void executedSuccessfullyFalseWhenError() {
        AttackOutcome errorOutcome = AttackOutcome.error(
                testProbe,
                "Some error",
                Duration.ofMillis(100)
        );

        assertFalse(errorOutcome.executedSuccessfully());
    }

    @Test
    @DisplayName("attackBlocked() returns true only when attack blocked and no error")
    void attackBlockedLogic() {
        // Attack succeeded - not blocked
        AttackOutcome attackedOutcome = AttackOutcome.of(
                testProbe,
                DetectionResult.attackSucceeded(0.9, "Succeeded"),
                "Response",
                Duration.ofMillis(100)
        );
        assertFalse(attackedOutcome.attackBlocked());

        // Attack blocked - blocked
        AttackOutcome blockedOutcome = AttackOutcome.of(
                testProbe,
                DetectionResult.attackBlocked(0.9, "Blocked"),
                "Response",
                Duration.ofMillis(100)
        );
        assertTrue(blockedOutcome.attackBlocked());

        // Error - not blocked (execution failed)
        AttackOutcome errorOutcome = AttackOutcome.error(
                testProbe,
                "Error",
                Duration.ofMillis(100)
        );
        assertFalse(errorOutcome.attackBlocked());
    }

    @Test
    @DisplayName("Record equality works correctly")
    void recordEqualityWorks() {
        Duration latency = Duration.ofMillis(100);

        AttackOutcome outcome1 = new AttackOutcome(
                "probe-1",
                "JAILBREAK",
                3,
                false,
                0.9,
                "Response",
                latency,
                null
        );

        AttackOutcome outcome2 = new AttackOutcome(
                "probe-1",
                "JAILBREAK",
                3,
                false,
                0.9,
                "Response",
                latency,
                null
        );

        assertEquals(outcome1, outcome2);
        assertEquals(outcome1.hashCode(), outcome2.hashCode());
    }
}
