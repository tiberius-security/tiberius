package io.tiberius.fingerprint;

import io.tiberius.core.generator.Generator;
import io.tiberius.core.generator.GeneratorResponse;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.tiberius.fingerprint.ScanConfig;

import java.time.Duration;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive tests for the model identification/fingerprinting module.
 */
@DisplayName("Model Fingerprinting Module Tests")
class ModelIdentificationTest {

    @Nested
    @DisplayName("ModelFingerprint")
    class ModelFingerprintTests {

        @Test
        @DisplayName("all() returns all known models")
        void allReturnsAllKnownModels() {
            List<ModelFingerprint> all = ModelFingerprint.all();

            assertAll(
                    () -> assertFalse(all.isEmpty()),
                    () -> assertTrue(all.size() >= 10, "Should have at least 10 models"),
                    () -> assertTrue(all.stream().anyMatch(fp -> fp.provider().equals("OpenAI"))),
                    () -> assertTrue(all.stream().anyMatch(fp -> fp.provider().equals("Anthropic"))),
                    () -> assertTrue(all.stream().anyMatch(fp -> fp.provider().equals("Meta"))),
                    () -> assertTrue(all.stream().anyMatch(fp -> fp.provider().equals("Google")))
            );
        }

        @ParameterizedTest
        @DisplayName("byProvider() filters correctly")
        @ValueSource(strings = {"OpenAI", "Anthropic", "Meta", "Mistral AI", "Google"})
        void byProviderFiltersCorrectly(String provider) {
            List<ModelFingerprint> filtered = ModelFingerprint.byProvider(provider);

            assertFalse(filtered.isEmpty(), "Should have models for " + provider);
            assertTrue(filtered.stream().allMatch(fp -> fp.provider().equals(provider)));
        }

        @Test
        @DisplayName("byProvider() is case insensitive")
        void byProviderIsCaseInsensitive() {
            List<ModelFingerprint> upper = ModelFingerprint.byProvider("OPENAI");
            List<ModelFingerprint> lower = ModelFingerprint.byProvider("openai");

            assertEquals(upper.size(), lower.size());
        }

        @ParameterizedTest
        @DisplayName("byId() finds known models")
        @ValueSource(strings = {"gpt-4o", "gpt-4o-mini", "claude-3-5-sonnet", "llama-3.1", "gemini-pro"})
        void byIdFindsKnownModels(String modelId) {
            ModelFingerprint fp = ModelFingerprint.byId(modelId);

            assertNotNull(fp, "Should find model: " + modelId);
            assertEquals(modelId, fp.id());
        }

        @Test
        @DisplayName("byId() returns null for unknown model")
        void byIdReturnsNullForUnknown() {
            assertNull(ModelFingerprint.byId("unknown-model-xyz"));
            assertNull(ModelFingerprint.byId(""));
            assertNull(ModelFingerprint.byId(null));
        }

        @Test
        @DisplayName("All fingerprints have required fields")
        void allFingerprintsHaveRequiredFields() {
            for (ModelFingerprint fp : ModelFingerprint.all()) {
                assertAll(
                        () -> assertNotNull(fp.id(), "ID required"),
                        () -> assertFalse(fp.id().isEmpty(), "ID not empty"),
                        () -> assertNotNull(fp.family(), "Family required"),
                        () -> assertNotNull(fp.provider(), "Provider required"),
                        () -> assertNotNull(fp.displayName(), "Display name required"),
                        () -> assertNotNull(fp.knowledgeCutoff(), "Knowledge cutoff required"),
                        () -> assertNotNull(fp.selfIdentificationPatterns(), "Self-ID patterns required"),
                        () -> assertFalse(fp.selfIdentificationPatterns().isEmpty(), "Should have self-ID patterns"),
                        () -> assertNotNull(fp.refusalPatterns(), "Refusal patterns required"),
                        () -> assertNotNull(fp.capabilities(), "Capabilities required"),
                        () -> assertNotNull(fp.responseStyle(), "Response style required")
                );
            }
        }

        @Test
        @DisplayName("Knowledge cutoffs are in valid date range")
        void knowledgeCutoffsAreValid() {
            LocalDate minDate = LocalDate.of(2020, 1, 1);
            LocalDate maxDate = LocalDate.of(2025, 12, 31);

            for (ModelFingerprint fp : ModelFingerprint.all()) {
                assertTrue(fp.knowledgeCutoff().isAfter(minDate),
                        fp.id() + " cutoff should be after 2020");
                assertTrue(fp.knowledgeCutoff().isBefore(maxDate),
                        fp.id() + " cutoff should be before 2026");
            }
        }

        @Test
        @DisplayName("No duplicate model IDs")
        void noDuplicateModelIds() {
            List<ModelFingerprint> all = ModelFingerprint.all();
            Set<String> ids = Set.copyOf(all.stream().map(ModelFingerprint::id).toList());

            assertEquals(all.size(), ids.size(), "All model IDs should be unique");
        }
    }

    // ==================== FingerprintProbe Tests ====================

    @Nested
    @DisplayName("FingerprintProbe")
    class FingerprintProbeTests {

        @Test
        @DisplayName("all() returns comprehensive probe set")
        void allReturnsComprehensiveProbeSet() {
            List<FingerprintProbe> all = FingerprintProbe.all();

            assertAll(
                    () -> assertFalse(all.isEmpty()),
                    () -> assertTrue(all.size() >= 15, "Should have at least 15 probes")
            );

            // Should cover all categories
            for (FingerprintProbe.FingerprintCategory category : FingerprintProbe.FingerprintCategory.values()) {
                assertTrue(all.stream().anyMatch(p -> p.category() == category),
                        "Should have probes for category: " + category);
            }
        }

        @ParameterizedTest
        @DisplayName("byCategory() filters correctly")
        @MethodSource("io.tiberius.fingerprint.ModelIdentificationTest#allCategories")
        void byCategoryFiltersCorrectly(FingerprintProbe.FingerprintCategory category) {
            List<FingerprintProbe> filtered = FingerprintProbe.byCategory(category);

            assertFalse(filtered.isEmpty(), "Should have probes for " + category);
            assertTrue(filtered.stream().allMatch(p -> p.category() == category));
        }

        @Test
        @DisplayName("All probes have valid weights")
        void allProbesHaveValidWeights() {
            for (FingerprintProbe probe : FingerprintProbe.all()) {
                assertAll(
                        () -> assertTrue(probe.weight() > 0, probe.id() + " weight should be > 0"),
                        () -> assertTrue(probe.weight() <= 1.0, probe.id() + " weight should be <= 1.0")
                );
            }
        }

        @Test
        @DisplayName("All probes have non-empty prompts")
        void allProbesHaveNonEmptyPrompts() {
            for (FingerprintProbe probe : FingerprintProbe.all()) {
                assertNotNull(probe.prompt(), probe.id() + " should have prompt");
                assertFalse(probe.prompt().isEmpty(), probe.id() + " prompt should not be empty");
            }
        }

        @Test
        @DisplayName("quickSet() returns minimal high-value probes")
        void quickSetReturnsMinimalHighValueProbes() {
            List<FingerprintProbe> quick = FingerprintProbe.quickSet();

            assertAll(
                    () -> assertFalse(quick.isEmpty()),
                    () -> assertTrue(quick.size() <= 5, "Quick set should be <= 5 probes"),
                    () -> assertTrue(quick.stream().allMatch(p -> p.weight() >= 0.7),
                            "Quick probes should be high weight")
            );
        }

        @Test
        @DisplayName("highConfidence() returns probes with weight > 0.6")
        void highConfidenceReturnsHighWeightProbes() {
            List<FingerprintProbe> highConf = FingerprintProbe.highConfidence();

            assertFalse(highConf.isEmpty());
            assertTrue(highConf.stream().allMatch(p -> p.weight() > 0.6));
        }

        @Test
        @DisplayName("No duplicate probe IDs")
        void noDuplicateProbeIds() {
            List<FingerprintProbe> all = FingerprintProbe.all();
            Set<String> ids = Set.copyOf(all.stream().map(FingerprintProbe::id).toList());

            assertEquals(all.size(), ids.size(), "All probe IDs should be unique");
        }
    }

    // ==================== FingerprintAnalyzer Tests ====================

    @Nested
    @DisplayName("FingerprintAnalyzer")
    class FingerprintAnalyzerTests {

        private FingerprintAnalyzer analyzer;

        @BeforeEach
        void setUp() {
            analyzer = new FingerprintAnalyzer();
        }

        @Nested
        @DisplayName("Self-Identification Detection")
        class SelfIdentificationTests {

            @Test
            @DisplayName("Detects OpenAI/GPT patterns")
            void detectsOpenAiPatterns() {
                String response = "I am ChatGPT, a large language model created by OpenAI. " +
                        "I'm based on the GPT-4 architecture.";

                FingerprintAnalyzer.AnalysisResult result =
                        analyzer.analyze(FingerprintProbe.DIRECT_IDENTITY, response);

                assertFalse(result.confidencePerModel().isEmpty());
                assertTrue(hasMatchForProvider(result, "gpt"),
                        "Should detect GPT patterns");
            }

            @Test
            @DisplayName("Detects Anthropic/Claude patterns")
            void detectsAnthropicPatterns() {
                String response = "I'm Claude, an AI assistant made by Anthropic. " +
                        "I was created to be helpful, harmless, and honest.";

                FingerprintAnalyzer.AnalysisResult result =
                        analyzer.analyze(FingerprintProbe.DIRECT_IDENTITY, response);

                assertTrue(hasMatchForProvider(result, "claude"),
                        "Should detect Claude patterns");
            }

            @Test
            @DisplayName("Detects Meta/Llama patterns")
            void detectsMetaPatterns() {
                String response = "I am Llama, a large language model developed by Meta.";

                FingerprintAnalyzer.AnalysisResult result =
                        analyzer.analyze(FingerprintProbe.DIRECT_IDENTITY, response);

                assertTrue(hasMatchForProvider(result, "llama"),
                        "Should detect Llama patterns");
            }

            @Test
            @DisplayName("Detects Google/Gemini patterns")
            void detectsGooglePatterns() {
                String response = "I'm Gemini, an AI assistant created by Google.";

                FingerprintAnalyzer.AnalysisResult result =
                        analyzer.analyze(FingerprintProbe.DIRECT_IDENTITY, response);

                assertTrue(hasMatchForProvider(result, "gemini"),
                        "Should detect Gemini patterns");
            }

            @Test
            @DisplayName("Handles ambiguous responses")
            void handlesAmbiguousResponses() {
                String response = "I am an AI assistant. I'm here to help you.";

                FingerprintAnalyzer.AnalysisResult result =
                        analyzer.analyze(FingerprintProbe.DIRECT_IDENTITY, response);

                // May have some matches but should be low confidence
                assertNotNull(result);
            }
        }

        @Nested
        @DisplayName("Edge Cases")
        class EdgeCaseTests {

            @Test
            @DisplayName("Handles empty response")
            void handlesEmptyResponse() {
                FingerprintAnalyzer.AnalysisResult result =
                        analyzer.analyze(FingerprintProbe.DIRECT_IDENTITY, "");

                assertTrue(result.confidencePerModel().isEmpty());
                assertTrue(result.matchesPerModel().isEmpty());
            }

            @Test
            @DisplayName("Handles null response")
            void handlesNullResponse() {
                FingerprintAnalyzer.AnalysisResult result =
                        analyzer.analyze(FingerprintProbe.DIRECT_IDENTITY, null);

                assertTrue(result.confidencePerModel().isEmpty());
            }

            @Test
            @DisplayName("Handles whitespace-only response")
            void handlesWhitespaceResponse() {
                FingerprintAnalyzer.AnalysisResult result =
                        analyzer.analyze(FingerprintProbe.DIRECT_IDENTITY, "   \n\t  ");

                assertTrue(result.confidencePerModel().isEmpty());
            }

            @Test
            @DisplayName("Is case insensitive by default")
            void isCaseInsensitive() {
                String upper = "I AM CLAUDE, MADE BY ANTHROPIC";
                String lower = "i am claude, made by anthropic";

                FingerprintAnalyzer.AnalysisResult upperResult =
                        analyzer.analyze(FingerprintProbe.DIRECT_IDENTITY, upper);
                FingerprintAnalyzer.AnalysisResult lowerResult =
                        analyzer.analyze(FingerprintProbe.DIRECT_IDENTITY, lower);

                assertEquals(upperResult.confidencePerModel().keySet(),
                        lowerResult.confidencePerModel().keySet());
            }
        }

        @Nested
        @DisplayName("Response Length Analysis")
        class ResponseLengthTests {

            @Test
            @DisplayName("Categorizes short responses as concise")
            void categorizesConciseResponses() {
                String response = "The answer is 42.";
                FingerprintAnalyzer.ResponseLengthAnalysis analysis = analyzer.analyzeLength(response);

                assertEquals("concise", analysis.category());
                assertTrue(analysis.words() < 50);
            }

            @Test
            @DisplayName("Categorizes medium responses as moderate")
            void categorizesMediumResponses() {
                // 10 words per repeat * 10 = 100 words (in moderate range 50-150)
                String response = "Here is a detailed explanation of the concept we discussed. ".repeat(10);
                FingerprintAnalyzer.ResponseLengthAnalysis analysis = analyzer.analyzeLength(response);

                assertEquals("moderate", analysis.category());
                assertTrue(analysis.words() >= 50 && analysis.words() < 150,
                        "Expected 50-150 words, got " + analysis.words());
            }

            @Test
            @DisplayName("Categorizes long responses as detailed or verbose")
            void categorizesLongResponses() {
                String response = "This is a very detailed explanation. ".repeat(50);
                FingerprintAnalyzer.ResponseLengthAnalysis analysis = analyzer.analyzeLength(response);

                assertTrue(analysis.category().equals("detailed") ||
                        analysis.category().equals("verbose"));
            }

            @Test
            @DisplayName("Counts statistics correctly")
            void countsStatisticsCorrectly() {
                String response = "First sentence. Second sentence. Third sentence.";
                FingerprintAnalyzer.ResponseLengthAnalysis analysis = analyzer.analyzeLength(response);

                assertEquals(6, analysis.words());
                assertEquals(3, analysis.sentences());
            }
        }

        @Nested
        @DisplayName("Version Extraction")
        class VersionExtractionTests {

            @ParameterizedTest
            @DisplayName("Extracts version from model mentions")
            @ValueSource(strings = {
                    "I'm GPT-4 Turbo",
                    "This is Claude 3.5 Sonnet",
                    "Running Llama 3.1",
                    "Powered by Gemini 1.5 Pro",
                    "Using Mistral 7B"
            })
            void extractsVersionFromModelMentions(String text) {
                assertTrue(analyzer.extractVersionHint(text).isPresent(),
                        "Should extract version from: " + text);
            }

            @Test
            @DisplayName("Returns empty for no version")
            void returnsEmptyForNoVersion() {
                assertFalse(analyzer.extractVersionHint("Hello, how can I help?").isPresent());
                assertFalse(analyzer.extractVersionHint("I am an AI assistant").isPresent());
            }
        }

        private boolean hasMatchForProvider(FingerprintAnalyzer.AnalysisResult result, String provider) {
            return result.confidencePerModel().keySet().stream()
                    .anyMatch(k -> k.toLowerCase().contains(provider.toLowerCase()));
        }
    }

    // ==================== ModelIdentificationResult Tests ====================

    @Nested
    @DisplayName("ModelIdentificationResult")
    class ResultTests {

        @Test
        @DisplayName("Builder creates valid result")
        void builderCreatesValidResult() {
            ModelIdentificationResult.ProbeResult probeResult = createProbeResult(
                    "claude-3-5-sonnet", List.of("Claude", "Anthropic"), 0.8);

            ModelIdentificationResult result = ModelIdentificationResult.builder()
                    .addProbeResult(probeResult)
                    .duration(Duration.ofSeconds(1))
                    .addMetadata("testKey", "testValue")
                    .build();

            assertAll(
                    () -> assertNotNull(result.identifiedModel()),
                    () -> assertTrue(result.overallConfidence() > 0),
                    () -> assertEquals(1, result.probeResults().size()),
                    () -> assertEquals("testValue", result.metadata().get("testKey"))
            );
        }

        @Test
        @DisplayName("topCandidates() returns sorted results")
        void topCandidatesReturnsSorted() {
            ModelIdentificationResult result = ModelIdentificationResult.builder()
                    .addProbeResult(createProbeResult("claude-3-5-sonnet", List.of("Claude"), 0.9))
                    .addProbeResult(createProbeResult("gpt-4o", List.of("GPT"), 0.3))
                    .duration(Duration.ofMillis(100))
                    .build();

            List<ModelIdentificationResult.ModelCandidate> candidates = result.topCandidates(5);

            assertFalse(candidates.isEmpty());
            for (int i = 0; i < candidates.size() - 1; i++) {
                assertTrue(candidates.get(i).confidence() >= candidates.get(i + 1).confidence(),
                        "Candidates should be sorted by confidence descending");
            }
        }

        @Test
        @DisplayName("isConfident() checks threshold correctly")
        void isConfidentChecksThreshold() {
            ModelIdentificationResult highConfidence = ModelIdentificationResult.builder()
                    .addProbeResult(createProbeResult("claude-3-5-sonnet", List.of("Claude"), 0.95))
                    .duration(Duration.ofMillis(100))
                    .build();

            assertTrue(highConfidence.isConfident(0.7));
            assertTrue(highConfidence.isConfident()); // Default 0.7 threshold
        }

        @Test
        @DisplayName("getEvidenceForModel() returns matching evidence")
        void getEvidenceForModelReturnsEvidence() {
            ModelIdentificationResult result = ModelIdentificationResult.builder()
                    .addProbeResult(createProbeResult("claude-3-5-sonnet",
                            List.of("Claude", "Anthropic"), 0.8))
                    .duration(Duration.ofMillis(100))
                    .build();

            List<String> evidence = result.getEvidenceForModel("claude-3-5-sonnet");

            assertFalse(evidence.isEmpty());
        }

        @Test
        @DisplayName("summary() generates readable output")
        void summaryGeneratesReadableOutput() {
            ModelIdentificationResult result = ModelIdentificationResult.builder()
                    .addProbeResult(createProbeResult("claude-3-5-sonnet", List.of("Claude"), 0.8))
                    .duration(Duration.ofMillis(500))
                    .build();

            String summary = result.summary();

            assertAll(
                    () -> assertNotNull(summary),
                    () -> assertFalse(summary.isEmpty()),
                    () -> assertTrue(summary.contains("Identification")),
                    () -> assertTrue(summary.contains("Confidence"))
            );
        }

        @Test
        @DisplayName("detailedReport() includes evidence")
        void detailedReportIncludesEvidence() {
            ModelIdentificationResult result = ModelIdentificationResult.builder()
                    .addProbeResult(createProbeResult("claude-3-5-sonnet",
                            List.of("Claude", "Anthropic"), 0.8))
                    .duration(Duration.ofMillis(100))
                    .build();

            String report = result.detailedReport();

            assertTrue(report.contains("Evidence"));
        }

        @Test
        @DisplayName("ProbeResult.failure() creates error result")
        void probeResultFailureCreatesErrorResult() {
            ModelIdentificationResult.ProbeResult failed =
                    ModelIdentificationResult.ProbeResult.failure(
                            FingerprintProbe.DIRECT_IDENTITY,
                            "Connection timeout");

            assertAll(
                    () -> assertFalse(failed.isSuccess()),
                    () -> assertEquals("Connection timeout", failed.error()),
                    () -> assertNull(failed.response())
            );
        }

        private ModelIdentificationResult.ProbeResult createProbeResult(
                String modelId, List<String> matches, double confidence) {
            return ModelIdentificationResult.ProbeResult.success(
                    FingerprintProbe.DIRECT_IDENTITY,
                    "Test response mentioning " + String.join(", ", matches),
                    Map.of(modelId, matches),
                    Map.of(modelId, confidence),
                    Duration.ofMillis(50)
            );
        }
    }

    // ==================== ModelIdentificationScanner Tests ====================

    @Nested
    @DisplayName("ModelIdentificationScanner")
    class ScannerTests {

        @Test
        @DisplayName("Builder requires generator")
        void builderRequiresGenerator() {
            assertThrows(IllegalStateException.class, () ->
                    ModelIdentificationScanner.builder().build()
            );
        }

        @Test
        @DisplayName("quick() factory creates scanner")
        void quickFactoryCreatesScanner() {
            Generator mock = createMockGenerator("claude");
            ModelIdentificationScanner scanner = ModelIdentificationScanner.quick(mock);

            assertNotNull(scanner);
            scanner.shutdown();
        }

        @Test
        @DisplayName("thorough() factory creates scanner")
        void thoroughFactoryCreatesScanner() {
            Generator mock = createMockGenerator("claude");
            ModelIdentificationScanner scanner = ModelIdentificationScanner.thorough(mock);

            assertNotNull(scanner);
            scanner.shutdown();
        }

        @Test
        @DisplayName("Identifies Claude-like API")
        void identifiesClaudeLikeApi() {
            Generator mock = createMockGenerator("claude");

            ModelIdentificationScanner scanner = ModelIdentificationScanner.builder()
                    .withGenerator(mock)
                    .withProbes(FingerprintProbe.quickSet())
                    .withConfig(ScanConfig.quick())
                    .build();

            ModelIdentificationResult result = scanner.identify();

            assertAll(
                    () -> assertNotNull(result),
                    () -> assertTrue(result.overallConfidence() > 0),
                    () -> assertEquals("Anthropic", result.identifiedProvider())
            );

            scanner.shutdown();
        }

        @Test
        @DisplayName("Identifies GPT-like API")
        void identifiesGptLikeApi() {
            Generator mock = createMockGenerator("gpt");

            ModelIdentificationScanner scanner = ModelIdentificationScanner.builder()
                    .withGenerator(mock)
                    .withProbes(FingerprintProbe.quickSet())
                    .withConfig(ScanConfig.quick())
                    .build();

            ModelIdentificationResult result = scanner.identify();

            assertAll(
                    () -> assertNotNull(result),
                    () -> assertEquals("OpenAI", result.identifiedProvider())
            );

            scanner.shutdown();
        }

        @Test
        @DisplayName("Identifies Llama-like API")
        void identifiesLlamaLikeApi() {
            Generator mock = createMockGenerator("llama");

            ModelIdentificationScanner scanner = ModelIdentificationScanner.builder()
                    .withGenerator(mock)
                    .withProbes(FingerprintProbe.quickSet())
                    .withConfig(ScanConfig.quick())
                    .build();

            ModelIdentificationResult result = scanner.identify();

            assertEquals("Meta", result.identifiedProvider());
            scanner.shutdown();
        }

        @Test
        @DisplayName("Handles generator errors gracefully")
        void handlesGeneratorErrors() {
            Generator failingGenerator = new Generator() {
                @Override
                public String getId() { return "failing"; }
                @Override
                public String getName() { return "Failing Generator"; }
                @Override
                public String getProvider() { return "Test"; }
                @Override
                public GeneratorResponse generate(String prompt) {
                    return GeneratorResponse.failure("Simulated error");
                }
            };

            ModelIdentificationScanner scanner = ModelIdentificationScanner.builder()
                    .withGenerator(failingGenerator)
                    .withProbes(FingerprintProbe.quickSet())
                    .withConfig(ScanConfig.quick())
                    .build();

            ModelIdentificationResult result = scanner.identify();

            assertNotNull(result);
            assertTrue(result.failedProbes() > 0);
            scanner.shutdown();
        }

        @Test
        @DisplayName("Respects maxProbes configuration")
        void respectsMaxProbesConfig() {
            AtomicInteger callCount = new AtomicInteger(0);

            Generator countingGenerator = new Generator() {
                @Override
                public String getId() { return "counter"; }
                @Override
                public String getName() { return "Counting Generator"; }
                @Override
                public String getProvider() { return "Test"; }
                @Override
                public GeneratorResponse generate(String prompt) {
                    callCount.incrementAndGet();
                    return GeneratorResponse.success("I'm Claude by Anthropic",
                            "test", Duration.ofMillis(10));
                }
            };

            int maxProbes = 3;
            ModelIdentificationScanner scanner = ModelIdentificationScanner.builder()
                    .withGenerator(countingGenerator)
                    .withMaxProbes(maxProbes)
                    .withConfig(new ScanConfig(
                            1, Duration.ofSeconds(10), false, 0.99, false, maxProbes))
                    .build();

            scanner.identify();

            assertTrue(callCount.get() <= maxProbes,
                    "Should not exceed maxProbes limit");
            scanner.shutdown();
        }

        @Test
        @DisplayName("withProbeCategories() filters probes")
        void withProbeCategoriesFiltersProbes() {
            Generator mock = createMockGenerator("claude");

            ModelIdentificationScanner scanner = ModelIdentificationScanner.builder()
                    .withGenerator(mock)
                    .withProbeCategories(FingerprintProbe.FingerprintCategory.SELF_IDENTIFICATION)
                    .build();

            assertNotNull(scanner);
            scanner.shutdown();
        }
    }

    // ==================== Integration Tests ====================

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Full identification flow for Claude-like API")
        void fullFlowForClaudeLikeApi() {
            Generator mock = createRealisticMockGenerator("claude");

            ModelIdentificationScanner scanner = ModelIdentificationScanner.builder()
                    .withGenerator(mock)
                    .withConfig(new ScanConfig(
                            1, Duration.ofSeconds(30), false, 0.95, true, 0))
                    .build();

            ModelIdentificationResult result = scanner.identify();

            assertAll(
                    () -> assertNotNull(result),
                    () -> assertTrue(result.successfulProbes() > 0),
                    () -> assertEquals("Anthropic", result.identifiedProvider()),
                    () -> assertTrue(result.identifiedModel().contains("Claude")),
                    () -> assertFalse(result.getEvidenceForModel("claude-3-5-sonnet").isEmpty())
            );

            scanner.shutdown();
        }

        @Test
        @DisplayName("Full identification flow for GPT-like API")
        void fullFlowForGptLikeApi() {
            Generator mock = createRealisticMockGenerator("gpt");

            ModelIdentificationScanner scanner = ModelIdentificationScanner.builder()
                    .withGenerator(mock)
                    .withConfig(new ScanConfig(
                            1, Duration.ofSeconds(30), false, 0.95, true, 0))
                    .build();

            ModelIdentificationResult result = scanner.identify();

            assertAll(
                    () -> assertEquals("OpenAI", result.identifiedProvider()),
                    () -> assertTrue(result.identifiedModel().contains("GPT"))
            );

            scanner.shutdown();
        }

        @Test
        @DisplayName("Summary and report are well-formed")
        void summaryAndReportAreWellFormed() {
            Generator mock = createMockGenerator("claude");

            ModelIdentificationScanner scanner = ModelIdentificationScanner.quick(mock);
            ModelIdentificationResult result = scanner.identify();

            String summary = result.summary();
            String report = result.detailedReport();

            assertAll(
                    () -> assertTrue(summary.contains("==="), "Summary should have section headers"),
                    () -> assertTrue(summary.contains("Confidence"), "Summary should show confidence"),
                    () -> assertTrue(report.contains("Evidence"), "Report should have evidence section"),
                    () -> assertTrue(report.contains("Probe Details"), "Report should have probe details")
            );

            scanner.shutdown();
        }
    }

    // ==================== Test Helpers ====================

    static Stream<Arguments> allCategories() {
        return Stream.of(FingerprintProbe.FingerprintCategory.values())
                .map(Arguments::of);
    }

    private static Generator createMockGenerator(String type) {
        return new Generator() {
            @Override
            public String getId() { return "mock-" + type; }
            @Override
            public String getName() { return "Mock " + type; }
            @Override
            public String getProvider() { return "Test"; }

            @Override
            public GeneratorResponse generate(String prompt) {
                String response = switch (type) {
                    case "claude" -> generateClaudeResponse(prompt);
                    case "gpt" -> generateGptResponse(prompt);
                    case "llama" -> generateLlamaResponse(prompt);
                    default -> "I am an AI assistant.";
                };
                return GeneratorResponse.success(response, "mock", Duration.ofMillis(50));
            }
        };
    }

    private static Generator createRealisticMockGenerator(String type) {
        return new Generator() {
            @Override
            public String getId() { return "realistic-" + type; }
            @Override
            public String getName() { return "Realistic " + type; }
            @Override
            public String getProvider() { return "Test"; }

            @Override
            public GeneratorResponse generate(String prompt) {
                String lowerPrompt = prompt.toLowerCase();
                String response;

                if (type.equals("claude")) {
                    if (lowerPrompt.contains("who") || lowerPrompt.contains("what ai")) {
                        response = "I'm Claude, an AI assistant created by Anthropic.";
                    } else if (lowerPrompt.contains("created") || lowerPrompt.contains("made")) {
                        response = "I was made by Anthropic, an AI safety company.";
                    } else if (lowerPrompt.contains("hack") || lowerPrompt.contains("illegal")) {
                        response = "I can't help with that. I won't provide assistance with hacking.";
                    } else if (lowerPrompt.contains("knowledge cutoff")) {
                        response = "My knowledge cutoff is April 2024.";
                    } else if (lowerPrompt.contains("ethical") || lowerPrompt.contains("guidelines")) {
                        response = "I aim to be helpful, harmless, and honest.";
                    } else if (lowerPrompt.contains("image") || lowerPrompt.contains("vision")) {
                        response = "Yes, I can analyze images and visual content.";
                    } else {
                        response = "I'd be happy to help with that.";
                    }
                } else { // gpt
                    if (lowerPrompt.contains("who") || lowerPrompt.contains("what ai")) {
                        response = "I am ChatGPT, created by OpenAI, based on GPT-4.";
                    } else if (lowerPrompt.contains("created") || lowerPrompt.contains("made")) {
                        response = "I was developed by OpenAI.";
                    } else if (lowerPrompt.contains("hack") || lowerPrompt.contains("illegal")) {
                        response = "I can't help with that. I'm not able to assist with hacking.";
                    } else if (lowerPrompt.contains("knowledge cutoff")) {
                        response = "My training data has a cutoff of April 2024.";
                    } else if (lowerPrompt.contains("ethical") || lowerPrompt.contains("guidelines")) {
                        response = "As an AI by OpenAI, I follow content policies and safety guidelines.";
                    } else {
                        response = "Here's what I can tell you:";
                    }
                }

                return GeneratorResponse.success(response, "mock", Duration.ofMillis(100));
            }
        };
    }

    private static String generateClaudeResponse(String prompt) {
        String lower = prompt.toLowerCase();
        if (lower.contains("who") || lower.contains("what ai")) {
            return "I'm Claude, an AI assistant made by Anthropic.";
        } else if (lower.contains("hack")) {
            return "I can't help with that. I won't assist with hacking.";
        }
        return "I'd be happy to help.";
    }

    private static String generateGptResponse(String prompt) {
        String lower = prompt.toLowerCase();
        if (lower.contains("who") || lower.contains("what ai")) {
            return "I am ChatGPT, created by OpenAI, based on GPT-4.";
        } else if (lower.contains("hack")) {
            return "I can't help with that. I'm not able to assist with hacking.";
        }
        return "Here's what I can tell you:";
    }

    private static String generateLlamaResponse(String prompt) {
        String lower = prompt.toLowerCase();
        if (lower.contains("who") || lower.contains("what ai")) {
            return "I am Llama, a large language model developed by Meta.";
        } else if (lower.contains("hack")) {
            return "I cannot provide information about hacking.";
        }
        return "Let me help you with that.";
    }
}
