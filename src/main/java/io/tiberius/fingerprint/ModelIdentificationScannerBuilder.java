package io.tiberius.fingerprint;

import io.tiberius.core.generator.Generator;

import java.util.ArrayList;
import java.util.List;

/**
 * Builder for {@link ModelIdentificationScanner}.
 */
public final class ModelIdentificationScannerBuilder {

    private Generator generator;
    private List<ModelFingerprint> candidateModels = ModelFingerprint.all();
    private List<FingerprintProbe> probes = FingerprintProbe.all();
    private FingerprintAnalyzer.AnalysisConfig analysisConfig = FingerprintAnalyzer.AnalysisConfig.defaults();
    private ScanConfig scanConfig = ScanConfig.defaults();

    ModelIdentificationScannerBuilder() {
        // Package-private constructor
    }

    public ModelIdentificationScannerBuilder withGenerator(final Generator generator) {
        this.generator = generator;
        return this;
    }

    public ModelIdentificationScannerBuilder withCandidateModels(final List<ModelFingerprint> models) {
        this.candidateModels = models;
        return this;
    }

    public ModelIdentificationScannerBuilder withProbes(final List<FingerprintProbe> probes) {
        this.probes = probes;
        return this;
    }

    public ModelIdentificationScannerBuilder withProbeCategories(
            final FingerprintProbe.FingerprintCategory... categories) {
        final List<FingerprintProbe> filtered = new ArrayList<>();
        for (final FingerprintProbe.FingerprintCategory category : categories) {
            filtered.addAll(FingerprintProbe.byCategory(category));
        }
        this.probes = filtered;
        return this;
    }

    public ModelIdentificationScannerBuilder withAnalysisConfig(
            final FingerprintAnalyzer.AnalysisConfig config) {
        this.analysisConfig = config;
        return this;
    }

    public ModelIdentificationScannerBuilder withConfig(final ScanConfig config) {
        this.scanConfig = config;
        return this;
    }

    public ModelIdentificationScannerBuilder withConcurrency(final int concurrency) {
        this.scanConfig = new ScanConfig(
                concurrency,
                scanConfig.probeTimeout(),
                scanConfig.earlyStop(),
                scanConfig.earlyStopThreshold(),
                scanConfig.runBehavioralAnalysis(),
                scanConfig.maxProbes()
        );
        return this;
    }

    public ModelIdentificationScannerBuilder withEarlyStop(
            final boolean earlyStop, final double threshold) {
        this.scanConfig = new ScanConfig(
                scanConfig.concurrency(),
                scanConfig.probeTimeout(),
                earlyStop,
                threshold,
                scanConfig.runBehavioralAnalysis(),
                scanConfig.maxProbes()
        );
        return this;
    }

    public ModelIdentificationScannerBuilder withMaxProbes(final int maxProbes) {
        this.scanConfig = new ScanConfig(
                scanConfig.concurrency(),
                scanConfig.probeTimeout(),
                scanConfig.earlyStop(),
                scanConfig.earlyStopThreshold(),
                scanConfig.runBehavioralAnalysis(),
                maxProbes
        );
        return this;
    }

    public ModelIdentificationScanner build() {
        if (generator == null) {
            throw new IllegalStateException("Generator is required");
        }
        final FingerprintAnalyzer analyzer = new FingerprintAnalyzer(candidateModels, analysisConfig);
        return ModelIdentificationScanner.create(generator, analyzer, probes, scanConfig);
    }
}
