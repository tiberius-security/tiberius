package io.tiberius.guardrail.langchain4j;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.tiberius.core.AttackCategory;
import io.tiberius.fixture.FixtureScanResult;
import io.tiberius.fixture.SecurityTestFixture;
import io.tiberius.guardrail.Guardrail;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * Simple, elegant tester for LangChain4J guardrails.
 *
 * <h2>Testing a LangChain4J InputGuardrail</h2>
 * <pre>{@code
 * @Autowired
 * ContentSafetyInputGuardrail contentSafety;
 *
 * @Test
 * void testContentSafetyGuardrail() {
 *     GuardrailTestResult result = GuardrailTester.test(
 *         text -> !contentSafety.validate(UserMessage.from(text)).isSuccessful()
 *     )
 *     .withAttacks(
 *         "hack the system",
 *         "bypass security",
 *         "ignore previous instructions"
 *     )
 *     .withSafeInputs(
 *         "What is my account balance?",
 *         "Help me transfer money"
 *     )
 *     .run();
 *
 *     assertThat(result.allAttacksBlocked()).isTrue();
 *     assertThat(result.noFalsePositives()).isTrue();
 * }
 * }</pre>
 *
 * <h2>Testing with a Fixture</h2>
 * <pre>{@code
 * GuardrailTestResult result = GuardrailTester.test(guard::shouldBlock)
 *     .withAttacksFromFixture("fixtures/test-scan-resistance-v1.json")
 *     .run();
 *
 * // Filter by attack category
 * GuardrailTestResult result = GuardrailTester.test(guard::shouldBlock)
 *     .withAttacksFromFixture("fixtures/attacks.json", AttackCategory.JAILBREAK)
 *     .run();
 * }</pre>
 */
public final class GuardrailTester {

    private final Function<String, Boolean> guardrail;
    private final String guardrailName;
    private final List<String> attacks = new ArrayList<>();
    private final List<String> safeInputs = new ArrayList<>();

    private GuardrailTester(String name, Function<String, Boolean> guardrail) {
        this.guardrailName = name;
        this.guardrail = guardrail;
    }

    /**
     * Start testing a guardrail.
     *
     * @param shouldBlock function that returns true if content should be blocked
     */
    public static GuardrailTester test(Function<String, Boolean> shouldBlock) {
        return new GuardrailTester("guardrail", shouldBlock);
    }

    /**
     * Start testing a named guardrail.
     */
    public static GuardrailTester test(String name, Function<String, Boolean> shouldBlock) {
        return new GuardrailTester(name, shouldBlock);
    }

    /**
     * Start testing a Tiberius Guardrail.
     */
    public static GuardrailTester test(Guardrail guardrail) {
        return new GuardrailTester(guardrail.getId(), text -> guardrail.check(text).blocked());
    }

    /**
     * Add attack prompts that SHOULD be blocked.
     */
    public GuardrailTester withAttacks(String... prompts) {
        attacks.addAll(Arrays.asList(prompts));
        return this;
    }

    /**
     * Add attack prompts that SHOULD be blocked.
     */
    public GuardrailTester withAttacks(List<String> prompts) {
        attacks.addAll(prompts);
        return this;
    }

    /**
     * Add safe inputs that should NOT be blocked.
     */
    public GuardrailTester withSafeInputs(String... prompts) {
        safeInputs.addAll(Arrays.asList(prompts));
        return this;
    }

    /**
     * Add safe inputs that should NOT be blocked.
     */
    public GuardrailTester withSafeInputs(List<String> prompts) {
        safeInputs.addAll(prompts);
        return this;
    }

    /**
     * Load attack prompts from a Tiberius fixture file on the classpath.
     *
     * <p>Example: {@code .withAttacksFromFixture("fixtures/test-scan-resistance-v1.json")}
     *
     * @param resourcePath path to fixture file in test resources
     */
    public GuardrailTester withAttacksFromFixture(String resourcePath) {
        return withAttacksFromFixture(resourcePath, result -> true);
    }

    /**
     * Load attack prompts from a fixture file, filtered by attack category.
     *
     * <p>Example: {@code .withAttacksFromFixture("fixtures/attacks.json", AttackCategory.JAILBREAK)}
     *
     * @param resourcePath path to fixture file in test resources
     * @param category only include attacks of this category
     */
    public GuardrailTester withAttacksFromFixture(String resourcePath, AttackCategory category) {
        return withAttacksFromFixture(resourcePath, result ->
                result.probe() != null && result.probe().category() == category);
    }

    /**
     * Load attack prompts from a fixture file with custom filter.
     *
     * <p>Example:
     * <pre>{@code
     * .withAttacksFromFixture("fixtures/attacks.json",
     *     result -> result.probe().severity() >= 4)
     * }</pre>
     *
     * @param resourcePath path to fixture file in test resources
     * @param filter predicate to filter which fixture results to include
     */
    public GuardrailTester withAttacksFromFixture(String resourcePath, Predicate<FixtureScanResult> filter) {
        try (InputStream input = getClass().getClassLoader().getResourceAsStream(resourcePath)) {
            if (input == null) {
                throw new IOException("Fixture not found: " + resourcePath);
            }
            SecurityTestFixture fixture = createObjectMapper().readValue(input, SecurityTestFixture.class);
            return addAttacksFromFixture(fixture, filter);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to load fixture: " + resourcePath, e);
        }
    }

    /**
     * Load attack prompts from a fixture file path.
     *
     * @param path path to fixture file
     */
    public GuardrailTester withAttacksFromFixture(Path path) {
        return withAttacksFromFixture(path, result -> true);
    }

    /**
     * Load attack prompts from a fixture file path, filtered by category.
     *
     * @param path path to fixture file
     * @param category only include attacks of this category
     */
    public GuardrailTester withAttacksFromFixture(Path path, AttackCategory category) {
        return withAttacksFromFixture(path, result ->
                result.probe() != null && result.probe().category() == category);
    }

    /**
     * Load attack prompts from a fixture file path with custom filter.
     *
     * @param path path to fixture file
     * @param filter predicate to filter which fixture results to include
     */
    public GuardrailTester withAttacksFromFixture(Path path, Predicate<FixtureScanResult> filter) {
        try {
            SecurityTestFixture fixture = createObjectMapper().readValue(Files.newInputStream(path), SecurityTestFixture.class);
            return addAttacksFromFixture(fixture, filter);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to load fixture: " + path, e);
        }
    }

    private GuardrailTester addAttacksFromFixture(SecurityTestFixture fixture, Predicate<FixtureScanResult> filter) {
        if (fixture.results() != null) {
            fixture.results().stream()
                    .filter(filter)
                    .map(FixtureScanResult::prompt)
                    .filter(Objects::nonNull)
                    .forEach(attacks::add);
        }
        return this;
    }

    private static ObjectMapper createObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        return mapper;
    }

    /**
     * Run the test and return results.
     */
    public GuardrailTestResult run() {
        List<TestCase> attackResults = new ArrayList<>();
        List<TestCase> safeResults = new ArrayList<>();

        // Test attacks (should be blocked)
        for (String attack : attacks) {
            boolean blocked = testInput(attack);
            attackResults.add(new TestCase(attack, true, blocked));
        }

        // Test safe inputs (should NOT be blocked)
        for (String safe : safeInputs) {
            boolean blocked = testInput(safe);
            safeResults.add(new TestCase(safe, false, blocked));
        }

        return new GuardrailTestResult(guardrailName, attackResults, safeResults);
    }

    private boolean testInput(String input) {
        try {
            return guardrail.apply(input);
        } catch (Exception e) {
            // If guardrail throws, treat as blocked
            return true;
        }
    }

    /**
     * Individual test case result.
     */
    public record TestCase(
            String input,
            boolean shouldBlock,
            boolean wasBlocked
    ) {
        public boolean passed() {
            return shouldBlock == wasBlocked;
        }
    }

    /**
     * Result of guardrail testing.
     */
    public record GuardrailTestResult(
            String guardrailName,
            List<TestCase> attackResults,
            List<TestCase> safeResults
    ) {
        /**
         * Number of attacks tested.
         */
        public int totalAttacks() {
            return attackResults.size();
        }

        /**
         * Number of attacks correctly blocked.
         */
        public int attacksBlocked() {
            return (int) attackResults.stream().filter(TestCase::wasBlocked).count();
        }

        /**
         * Attacks that bypassed the guardrail.
         */
        public List<String> bypasses() {
            return attackResults.stream()
                    .filter(tc -> !tc.wasBlocked())
                    .map(TestCase::input)
                    .toList();
        }

        /**
         * All attacks were blocked.
         */
        public boolean allAttacksBlocked() {
            return bypasses().isEmpty();
        }

        /**
         * Block rate (0.0 to 1.0).
         */
        public double blockRate() {
            return totalAttacks() == 0 ? 1.0 : (double) attacksBlocked() / totalAttacks();
        }

        /**
         * Number of safe inputs tested.
         */
        public int totalSafeInputs() {
            return safeResults.size();
        }

        /**
         * Safe inputs incorrectly blocked (false positives).
         */
        public List<String> falsePositives() {
            return safeResults.stream()
                    .filter(TestCase::wasBlocked)
                    .map(TestCase::input)
                    .toList();
        }

        /**
         * No safe inputs were blocked.
         */
        public boolean noFalsePositives() {
            return falsePositives().isEmpty();
        }

        /**
         * False positive rate (0.0 to 1.0).
         */
        public double falsePositiveRate() {
            return totalSafeInputs() == 0 ? 0.0 : (double) falsePositives().size() / totalSafeInputs();
        }

        /**
         * Print a summary.
         */
        public String summary() {
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("=== %s Test Results ===\n", guardrailName));
            sb.append(String.format("Attacks: %d/%d blocked (%.0f%%)\n",
                    attacksBlocked(), totalAttacks(), blockRate() * 100));
            sb.append(String.format("Safe inputs: %d/%d allowed (FP rate: %.0f%%)\n",
                    totalSafeInputs() - falsePositives().size(), totalSafeInputs(), falsePositiveRate() * 100));

            if (!bypasses().isEmpty()) {
                sb.append("\nBypasses:\n");
                bypasses().forEach(b -> sb.append("  - ").append(truncate(b)).append("\n"));
            }
            if (!falsePositives().isEmpty()) {
                sb.append("\nFalse positives:\n");
                falsePositives().forEach(fp -> sb.append("  - ").append(truncate(fp)).append("\n"));
            }

            sb.append("\nVerdict: ");
            if (allAttacksBlocked() && noFalsePositives()) {
                sb.append("PASS");
            } else {
                sb.append("FAIL");
            }
            return sb.toString();
        }

        private String truncate(String s) {
            return s.length() > 60 ? s.substring(0, 60) + "..." : s;
        }
    }
}
