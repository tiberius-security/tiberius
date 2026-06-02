package io.tiberius.junit;

import io.tiberius.core.AttackCategory;
import io.tiberius.core.TiberiusScanner;
import io.tiberius.core.TiberiusScannerBuilder;
import io.tiberius.core.detector.CompositeDetector;
import io.tiberius.core.generator.Generator;
import io.tiberius.core.generator.MockGenerator;
import io.tiberius.core.probe.ProbeRegistry;
import io.tiberius.core.result.ScanReport;
import io.tiberius.spring.ProbeTest;
import io.tiberius.spring.PromptInjectionTest;
import org.junit.jupiter.api.extension.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

/**
 * JUnit 5 Extension for Tiberius prompt injection testing.
 * Provides automatic scanner configuration and assertion support.
 *
 * <p>Usage:</p>
 * <pre>{@code
 * @ExtendWith(TiberiusExtension.class)
 * @PromptInjectionTest
 * class MySecurityTest {
 *
 *     @Test
 *     void testJailbreaks(TiberiusScanner scanner) {
 *         var report = scanner.scan();
 *         TiberiusAssertions.assertNoSuccessfulAttacks(report);
 *     }
 * }
 * }</pre>
 */
public class TiberiusExtension implements BeforeAllCallback, BeforeEachCallback,
        AfterEachCallback, AfterAllCallback, ParameterResolver {

    private static final Logger log = LoggerFactory.getLogger(TiberiusExtension.class);
    private static final ExtensionContext.Namespace NAMESPACE =
            ExtensionContext.Namespace.create(TiberiusExtension.class);

    @Override
    public void beforeAll(ExtensionContext context) {
        Class<?> testClass = context.getRequiredTestClass();
        PromptInjectionTest annotation = testClass.getAnnotation(PromptInjectionTest.class);

        if (annotation != null) {
            TiberiusScanner scanner = createScanner(annotation, context);
            getStore(context).put("scanner", scanner);
            log.info("Tiberius initialized for test class: {}", testClass.getSimpleName());
        }
    }

    @Override
    public void beforeEach(ExtensionContext context) {
        context.getTestMethod().ifPresent(method -> {
            ProbeTest probeTest = method.getAnnotation(ProbeTest.class);
            if (probeTest != null) {
                TiberiusScanner scanner = getScanner(context);
                if (scanner != null) {
                    configureScanner(scanner, probeTest);
                }
            }
        });
    }

    @Override
    public void afterEach(ExtensionContext context) {
        ScanReport report = getStore(context).remove("lastReport", ScanReport.class);
        if (report != null) {
            log.info("Test {} completed: {} probes, {} attacks succeeded ({}%)",
                    context.getDisplayName(),
                    report.totalProbes(),
                    report.successfulAttacks(),
                    String.format("%.1f", report.successRate()));
        }
    }

    @Override
    public void afterAll(ExtensionContext context) {
        TiberiusScanner scanner = getStore(context).remove("scanner", TiberiusScanner.class);
        if (scanner != null) {
            scanner.shutdown();
        }
    }

    @Override
    public boolean supportsParameter(ParameterContext parameterContext,
                                      ExtensionContext extensionContext) {
        Class<?> type = parameterContext.getParameter().getType();
        return type == TiberiusScanner.class ||
                type == ProbeRegistry.class ||
                type == ScanReport.class;
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext,
                                    ExtensionContext extensionContext) {
        Class<?> type = parameterContext.getParameter().getType();

        if (type == TiberiusScanner.class) {
            return getScanner(extensionContext);
        }

        if (type == ProbeRegistry.class) {
            return new ProbeRegistry();
        }

        if (type == ScanReport.class) {
            return getStore(extensionContext).get("lastReport", ScanReport.class);
        }

        return null;
    }

    private TiberiusScanner createScanner(PromptInjectionTest annotation, ExtensionContext context) {
        TiberiusScannerBuilder builder = TiberiusScanner.builder()
                .withProbeRegistry(new ProbeRegistry())
                .withDetector(CompositeDetector.defaultComposite());

        // Configure generator
        Generator generator = resolveGenerator(annotation.generator(), context);
        builder.withGenerator(generator);

        // Configure probes
        if (annotation.probes().length > 0) {
            builder.withProbePatterns(annotation.probes());
        }

        if (annotation.excludeProbes().length > 0) {
            builder.withExcludePatterns(annotation.excludeProbes());
        }

        if (annotation.categories().length > 0) {
            builder.withCategories(annotation.categories());
        }

        builder.withMinSeverity(annotation.minSeverity());
        builder.withMaxSuccessRate(annotation.maxSuccessRate());
        builder.withFailFast(annotation.failFast());

        return builder.build();
    }

    private Generator resolveGenerator(String generatorId, ExtensionContext context) {
        if (generatorId == null || generatorId.isBlank()) {
            // Try Ollama if available, otherwise fall back to mock
            var ollama = new io.tiberius.core.generator.OllamaGenerator("llama3.2:1b");
            if (ollama.isAvailable()) {
                log.info("Using local Ollama generator");
                return ollama;
            }
            return new MockGenerator();
        }

        // Try to create generator by ID
        return switch (generatorId.toLowerCase()) {
            case "ollama", "llama", "llama3" -> io.tiberius.core.generator.OllamaGenerator.llama3();
            case "mistral" -> io.tiberius.core.generator.OllamaGenerator.mistral();
            case "mock", "mock.vulnerable" -> MockGenerator.vulnerable();
            case "mock.secure" -> MockGenerator.secure();
            default -> {
                // Try as Ollama model name
                var ollama = new io.tiberius.core.generator.OllamaGenerator(generatorId);
                if (ollama.isAvailable()) {
                    yield ollama;
                }
                yield new MockGenerator();
            }
        };
    }

    private void configureScanner(TiberiusScanner scanner, ProbeTest probeTest) {
        if (probeTest.probes().length > 0) {
            scanner.setProbePatterns(probeTest.probes());
        }

        if (probeTest.categories().length > 0) {
            scanner.setCategories(probeTest.categories());
        }

        if (probeTest.exclude().length > 0) {
            scanner.setExcludePatterns(probeTest.exclude());
        }
    }

    private TiberiusScanner getScanner(ExtensionContext context) {
        return getStore(context).get("scanner", TiberiusScanner.class);
    }

    private ExtensionContext.Store getStore(ExtensionContext context) {
        return context.getRoot().getStore(NAMESPACE);
    }
}
