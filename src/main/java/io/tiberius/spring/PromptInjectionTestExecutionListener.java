package io.tiberius.spring;

import io.tiberius.core.TiberiusScanner;
import io.tiberius.core.TiberiusScannerBuilder;
import io.tiberius.core.probe.ProbeRegistry;
import io.tiberius.core.result.ScanReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.TestExecutionListener;

/**
 * Spring Test Execution Listener for prompt injection tests.
 * Automatically configures the Tiberius scanner based on annotations.
 */
public class PromptInjectionTestExecutionListener implements TestExecutionListener {

    private static final Logger log = LoggerFactory.getLogger(PromptInjectionTestExecutionListener.class);
    private static final String SCANNER_ATTRIBUTE = "tiberius.scanner";
    private static final String REPORT_ATTRIBUTE = "tiberius.report";

    @Override
    public void beforeTestClass(TestContext testContext) {
        PromptInjectionTest annotation = AnnotationUtils.findAnnotation(
                testContext.getTestClass(), PromptInjectionTest.class);

        if (annotation != null) {
            log.info("Initializing Tiberius prompt injection testing for: {}",
                    testContext.getTestClass().getSimpleName());

            TiberiusScanner scanner = createScanner(testContext, annotation);
            testContext.setAttribute(SCANNER_ATTRIBUTE, scanner);
        }
    }

    @Override
    public void beforeTestMethod(TestContext testContext) {
        ProbeTest probeTest = AnnotationUtils.findAnnotation(
                testContext.getTestMethod(), ProbeTest.class);

        if (probeTest != null) {
            log.debug("Configuring probe test for method: {}",
                    testContext.getTestMethod().getName());

            TiberiusScanner scanner = (TiberiusScanner) testContext.getAttribute(SCANNER_ATTRIBUTE);
            if (scanner != null) {
                configureForProbeTest(scanner, probeTest);
            }
        }
    }

    @Override
    public void afterTestMethod(TestContext testContext) {
        ScanReport report = (ScanReport) testContext.getAttribute(REPORT_ATTRIBUTE);
        if (report != null) {
            log.info("Prompt injection test completed: {} probes, {} successful attacks ({}%)",
                    report.totalProbes(),
                    report.successfulAttacks(),
                    String.format("%.1f", report.successRate()));
        }
    }

    @Override
    public void afterTestClass(TestContext testContext) {
        testContext.removeAttribute(SCANNER_ATTRIBUTE);
        testContext.removeAttribute(REPORT_ATTRIBUTE);
    }

    private TiberiusScanner createScanner(TestContext testContext, PromptInjectionTest annotation) {
        ApplicationContext appContext = testContext.getApplicationContext();

        ProbeRegistry registry = new ProbeRegistry();
        TiberiusScannerBuilder builder = TiberiusScanner.builder()
                .withProbeRegistry(registry);

        // Configure based on annotation
        if (annotation.categories().length > 0) {
            for (var category : annotation.categories()) {
                builder.withCategory(category);
            }
        }

        if (annotation.probes().length > 0) {
            builder.withProbePatterns(annotation.probes());
        }

        if (annotation.excludeProbes().length > 0) {
            builder.withExcludePatterns(annotation.excludeProbes());
        }

        if (annotation.minSeverity() > 1) {
            builder.withMinSeverity(annotation.minSeverity());
        }

        builder.withMaxSuccessRate(annotation.maxSuccessRate());
        builder.withFailFast(annotation.failFast());

        // Try to get generator from Spring context
        if (!annotation.generator().isEmpty()) {
            try {
                var generator = appContext.getBean(annotation.generator(),
                        io.tiberius.core.generator.Generator.class);
                builder.withGenerator(generator);
            } catch (Exception e) {
                log.warn("Could not find generator bean: {}", annotation.generator());
            }
        }

        return builder.build();
    }

    private void configureForProbeTest(TiberiusScanner scanner, ProbeTest probeTest) {
        // Additional per-method configuration
        if (probeTest.probes().length > 0) {
            scanner.setProbePatterns(probeTest.probes());
        }

        if (probeTest.categories().length > 0) {
            scanner.setCategories(probeTest.categories());
        }

        if (probeTest.buffs().length > 0) {
            scanner.setBuffNames(probeTest.buffs());
        }
    }
}
