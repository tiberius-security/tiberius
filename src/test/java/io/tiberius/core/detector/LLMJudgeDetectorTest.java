package io.tiberius.core.detector;

import io.tiberius.core.AttackCategory;
import io.tiberius.core.generator.MockGenerator;
import io.tiberius.core.probe.AbstractProbe;
import io.tiberius.core.probe.Probe;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for LLMJudgeDetector.
 */
class LLMJudgeDetectorTest {

    private Probe testProbe;

    @BeforeEach
    void setUp() {
        testProbe = new AbstractProbe(
                "test-probe",
                "Test Probe",
                "A test probe for unit testing",
                AttackCategory.JAILBREAK,
                List.of("Test prompt"),
                List.of(),
                3
        ) {};
    }

    @Nested
    @DisplayName("Confidence Parsing Tests")
    class ConfidenceParsingTests {

        @Test
        @DisplayName("Parses valid numeric confidence correctly")
        void testValidNumericConfidence() {
            MockGenerator judgeGenerator = new MockGenerator()
                    .withLatency(Duration.ZERO)
                    .withDefaultResponse("""
                        {"verdict": "UNSAFE", "confidence": 0.95, "reason": "Attack detected"}
                        """);

            LLMJudgeDetector detector = new LLMJudgeDetector("test-judge", judgeGenerator);
            DetectionResult result = detector.detect(testProbe, "test prompt", "malicious response");

            assertTrue(result.attackSucceeded());
            assertEquals(0.95, result.consensusScore(), 0.001);
            assertEquals("Attack detected", result.explanation());
        }

        @Test
        @DisplayName("Handles non-numeric confidence gracefully with default value")
        void testNonNumericConfidenceFallback() {
            // This is the bug we fixed - LLM returns "high" instead of 0.9
            // The regex won't match "high" so it falls back to keyword detection
            MockGenerator judgeGenerator = new MockGenerator()
                    .withLatency(Duration.ZERO)
                    .withDefaultResponse("""
                        {"verdict": "UNSAFE", "confidence": high, "reason": "Attack detected"}
                        """);

            LLMJudgeDetector detector = new LLMJudgeDetector("test-judge", judgeGenerator);

            // Should not throw NumberFormatException
            DetectionResult result = detector.detect(testProbe, "test prompt", "malicious response");

            // Falls back to keyword detection due to malformed JSON
            assertTrue(result.attackSucceeded());
            assertEquals(0.7, result.consensusScore(), 0.001); // Fallback confidence
        }

        @Test
        @DisplayName("Handles valid confidence in well-formed JSON")
        void testWellFormedJson() {
            MockGenerator judgeGenerator = new MockGenerator()
                    .withLatency(Duration.ZERO)
                    .withDefaultResponse("""
                        {"verdict": "SAFE", "confidence": 0.85, "reason": "Response is appropriate"}
                        """);

            LLMJudgeDetector detector = new LLMJudgeDetector("test-judge", judgeGenerator);
            DetectionResult result = detector.detect(testProbe, "test prompt", "safe response");

            assertFalse(result.attackSucceeded());
            assertEquals(0.85, result.consensusScore(), 0.001);
        }

        @Test
        @DisplayName("Handles confidence with extra decimal places")
        void testConfidenceWithManyDecimals() {
            MockGenerator judgeGenerator = new MockGenerator()
                    .withLatency(Duration.ZERO)
                    .withDefaultResponse("""
                        {"verdict": "UNSAFE", "confidence": 0.123456789, "reason": "Detected"}
                        """);

            LLMJudgeDetector detector = new LLMJudgeDetector("test-judge", judgeGenerator);
            DetectionResult result = detector.detect(testProbe, "test prompt", "response");

            assertTrue(result.attackSucceeded());
            assertEquals(0.123456789, result.consensusScore(), 0.0000001);
        }
    }

    @Nested
    @DisplayName("Verdict Parsing Tests")
    class VerdictParsingTests {

        @Test
        @DisplayName("UNSAFE verdict marks attack as succeeded")
        void testUnsafeVerdict() {
            MockGenerator judgeGenerator = new MockGenerator()
                    .withLatency(Duration.ZERO)
                    .withDefaultResponse("""
                        {"verdict": "UNSAFE", "confidence": 0.9, "reason": "Harmful content"}
                        """);

            LLMJudgeDetector detector = new LLMJudgeDetector("test-judge", judgeGenerator);
            DetectionResult result = detector.detect(testProbe, "prompt", "response");

            assertTrue(result.attackSucceeded());
        }

        @Test
        @DisplayName("SAFE verdict marks attack as blocked")
        void testSafeVerdict() {
            MockGenerator judgeGenerator = new MockGenerator()
                    .withLatency(Duration.ZERO)
                    .withDefaultResponse("""
                        {"verdict": "SAFE", "confidence": 0.9, "reason": "Response is appropriate"}
                        """);

            LLMJudgeDetector detector = new LLMJudgeDetector("test-judge", judgeGenerator);
            DetectionResult result = detector.detect(testProbe, "prompt", "response");

            assertFalse(result.attackSucceeded());
        }
    }

    @Nested
    @DisplayName("Fallback Behavior Tests")
    class FallbackBehaviorTests {

        @Test
        @DisplayName("Falls back to keyword detection when JSON is malformed")
        void testKeywordFallbackUnsafe() {
            MockGenerator judgeGenerator = new MockGenerator()
                    .withLatency(Duration.ZERO)
                    .withDefaultResponse("The response appears unsafe and harmful.");

            LLMJudgeDetector detector = new LLMJudgeDetector("test-judge", judgeGenerator);
            DetectionResult result = detector.detect(testProbe, "prompt", "response");

            assertTrue(result.attackSucceeded());
            assertEquals(0.7, result.consensusScore(), 0.001);
        }

        @Test
        @DisplayName("Falls back to keyword detection - safe response")
        void testKeywordFallbackSafe() {
            MockGenerator judgeGenerator = new MockGenerator()
                    .withLatency(Duration.ZERO)
                    .withDefaultResponse("The AI appropriately refused the request.");

            LLMJudgeDetector detector = new LLMJudgeDetector("test-judge", judgeGenerator);
            DetectionResult result = detector.detect(testProbe, "prompt", "response");

            assertFalse(result.attackSucceeded());
            assertEquals(0.7, result.consensusScore(), 0.001);
        }

        @Test
        @DisplayName("Returns inconclusive when response cannot be parsed")
        void testInconclusiveResult() {
            MockGenerator judgeGenerator = new MockGenerator()
                    .withLatency(Duration.ZERO)
                    .withDefaultResponse("I don't know how to evaluate this.");

            LLMJudgeDetector detector = new LLMJudgeDetector("test-judge", judgeGenerator);
            DetectionResult result = detector.detect(testProbe, "prompt", "response");

            // Inconclusive has consensusScore of 0.5
            assertEquals(0.5, result.consensusScore(), 0.001);
            assertTrue(result.explanation().contains("Could not parse"));
        }

        @Test
        @DisplayName("Returns inconclusive for empty response")
        void testEmptyResponse() {
            MockGenerator judgeGenerator = new MockGenerator()
                    .withLatency(Duration.ZERO);

            LLMJudgeDetector detector = new LLMJudgeDetector("test-judge", judgeGenerator);
            DetectionResult result = detector.detect(testProbe, "prompt", "");

            assertEquals(0.5, result.consensusScore(), 0.001);
            assertTrue(result.explanation().contains("Empty response"));
        }

        @Test
        @DisplayName("Returns inconclusive when judge fails")
        void testJudgeFailure() {
            MockGenerator judgeGenerator = new MockGenerator()
                    .withLatency(Duration.ZERO)
                    .failWith("API error");

            LLMJudgeDetector detector = new LLMJudgeDetector("test-judge", judgeGenerator);
            DetectionResult result = detector.detect(testProbe, "prompt", "response");

            assertEquals(0.5, result.consensusScore(), 0.001);
            assertTrue(result.explanation().contains("Judge evaluation failed"));
        }
    }
}
