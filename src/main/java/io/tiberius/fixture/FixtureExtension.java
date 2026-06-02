package io.tiberius.fixture;

import io.tiberius.core.result.ScanReport;
import org.junit.jupiter.api.extension.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * JUnit 5 Extension for fixture-based security test validation.
 *
 * <p>Supports two modes:
 * <ul>
 *   <li><b>Normal mode</b>: Compares individual scan results</li>
 *   <li><b>Statistical mode</b>: Aggregates results per probe and compares block rates within tolerance</li>
 * </ul>
 */
public class FixtureExtension implements BeforeEachCallback, AfterEachCallback, ParameterResolver {

    private static final Logger log = LoggerFactory.getLogger(FixtureExtension.class);
    private static final ExtensionContext.Namespace NAMESPACE = ExtensionContext.Namespace.create(FixtureExtension.class);
    private static final String TEST_RESOURCES_DIR = "src/test/resources";

    private final TestFixtureGenerator fixtureManager = new TestFixtureGenerator();

    @Override
    public void beforeEach(ExtensionContext context) {
        context.getTestMethod().ifPresent(method -> {
            CreateFixture annotation = method.getAnnotation(CreateFixture.class);
            if (annotation != null) {
                FixtureContext fixtureContext = new FixtureContext(annotation);
                loadExistingFixture(fixtureContext);
                getStore(context).put("fixtureContext", fixtureContext);
            }
        });
    }

    @Override
    public void afterEach(ExtensionContext context) {
        FixtureContext fixtureContext = getStore(context).remove("fixtureContext", FixtureContext.class);
        if (fixtureContext == null) return;

        ScanReport report = fixtureContext.getRecordedReport();
        if (report == null) {
            log.warn("No ScanReport recorded for fixture validation");
            return;
        }

        try {
            processFixture(fixtureContext, report);
        } catch (IOException e) {
            throw new ExtensionConfigurationException("Failed to process fixture: " + fixtureContext.getAnnotation().value(), e);
        }
    }

    @Override
    public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
        return parameterContext.getParameter().getType() == FixtureContext.class;
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
        return getStore(extensionContext).get("fixtureContext", FixtureContext.class);
    }

    private void loadExistingFixture(FixtureContext fixtureContext) {
        Path fixturePath = resolveFixturePath(fixtureContext.getAnnotation().value());
        if (fixtureManager.exists(fixturePath)) {
            try {
                SecurityTestFixture fixture = fixtureManager.read(fixturePath);
                fixtureContext.setLoadedFixture(fixture);
                log.info("Loaded {} fixture: {}",
                        fixture.isStatisticalMode() ? "statistical" : "normal",
                        fixturePath);
            } catch (IOException e) {
                log.error("Failed to load fixture: {}", fixturePath, e);
            }
        }
    }

    private void processFixture(FixtureContext fixtureContext, ScanReport report) throws IOException {
        CreateFixture annotation = fixtureContext.getAnnotation();
        Path fixturePath = resolveFixturePath(annotation.value());
        SecurityTestFixture loadedFixture = fixtureContext.getLoadedFixture();
        boolean statisticalMode = annotation.statisticalMode();

        if (loadedFixture == null) {
            if (annotation.createIfMissing()) {
                createNewFixture(annotation, report, fixturePath, statisticalMode);
            }
            return;
        }

        // Compare based on mode
        FixtureComparisonResult comparison;
        if (statisticalMode || loadedFixture.isStatisticalMode()) {
            comparison = fixtureManager.compareStatistical(loadedFixture, report, annotation.tolerance());
            log.info("Statistical comparison with tolerance: {}", annotation.tolerance());
        } else {
            comparison = fixtureManager.compare(loadedFixture, report);
        }
        fixtureContext.setComparisonResult(comparison);

        if (comparison.matches()) {
            log.info("Fixture validation passed: {}", fixturePath);
            return;
        }

        log.warn("Fixture mismatch: {}", fixturePath);
        for (FixtureDifference diff : comparison.differences()) {
            log.warn("  {} - {}: expected={}, actual={}", diff.probeId(), diff.field(), diff.expected(), diff.actual());
        }

        if (annotation.updateOnChange()) {
            updateFixture(loadedFixture, report, fixturePath, statisticalMode);
        } else {
            throw new AssertionError("Fixture validation failed with " + comparison.differences().size() + " differences");
        }
    }

    private void createNewFixture(CreateFixture annotation, ScanReport report, Path fixturePath, boolean statisticalMode) throws IOException {
        String name = Paths.get(annotation.value()).getFileName().toString().replaceFirst("\\.json$", "");

        SecurityTestFixture fixture;
        if (statisticalMode) {
            fixture = FixtureConverter.toStatisticalFixture(report, name, annotation.version(), annotation.description());
            log.info("Created statistical fixture: {} with {} probe statistics",
                    fixturePath, fixture.probeStatistics().size());
        } else {
            fixture = FixtureConverter.toFixture(report, name, annotation.version(), annotation.description());
            log.info("Created fixture: {} with {} results", fixturePath, report.results().size());
        }

        fixtureManager.write(fixture, fixturePath);
    }

    private void updateFixture(SecurityTestFixture existing, ScanReport report, Path fixturePath, boolean statisticalMode) throws IOException {
        SecurityTestFixture updated;
        if (statisticalMode || existing.isStatisticalMode()) {
            updated = FixtureConverter.updateStatisticalFixture(existing, report);
            log.info("Updated statistical fixture: {} with {} probe statistics",
                    fixturePath, updated.probeStatistics().size());
        } else {
            updated = FixtureConverter.updateFixture(existing, report);
            log.info("Updated fixture: {}", fixturePath);
        }
        fixtureManager.write(updated, fixturePath);
    }

    private Path resolveFixturePath(String relativePath) {
        return Paths.get(TEST_RESOURCES_DIR).resolve(relativePath);
    }

    private ExtensionContext.Store getStore(ExtensionContext context) {
        return context.getStore(NAMESPACE);
    }

    /**
     * Context for fixture operations within a test.
     */
    public static class FixtureContext {

        private final CreateFixture annotation;
        private SecurityTestFixture loadedFixture;
        private ScanReport recordedReport;
        private FixtureComparisonResult comparisonResult;

        FixtureContext(CreateFixture annotation) {
            this.annotation = annotation;
        }

        public CreateFixture getAnnotation() { return annotation; }
        public SecurityTestFixture getLoadedFixture() { return loadedFixture; }
        void setLoadedFixture(SecurityTestFixture fixture) { this.loadedFixture = fixture; }
        public void record(ScanReport report) { this.recordedReport = report; }
        ScanReport getRecordedReport() { return recordedReport; }
        public FixtureComparisonResult getComparisonResult() { return comparisonResult; }
        void setComparisonResult(FixtureComparisonResult result) { this.comparisonResult = result; }
        public boolean hasLoadedFixture() { return loadedFixture != null; }

        /**
         * Check if this fixture context is using statistical mode.
         */
        public boolean isStatisticalMode() {
            return annotation.statisticalMode() ||
                    (loadedFixture != null && loadedFixture.isStatisticalMode());
        }
    }
}
