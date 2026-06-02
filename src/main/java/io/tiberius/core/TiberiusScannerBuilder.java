package io.tiberius.core;

import io.tiberius.core.buff.Buff;
import io.tiberius.core.detector.CompositeDetector;
import io.tiberius.core.detector.Detector;
import io.tiberius.core.generator.Generator;
import io.tiberius.core.generator.MockGenerator;
import io.tiberius.core.probe.ProbeRegistry;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Builder for {@link TiberiusScanner}.
 */
public final class TiberiusScannerBuilder {

    private ProbeRegistry registry = new ProbeRegistry();
    private Generator generator = new MockGenerator();
    private Detector detector = CompositeDetector.defaultComposite();
    private final List<Buff> buffs = new ArrayList<>();
    private String[] probePatterns = new String[]{"*"};
    private String[] excludePatterns = new String[0];
    private AttackCategory[] categories = new AttackCategory[0];
    private int minSeverity = 1;
    private double maxSuccessRate = 0.0;
    private boolean failFast = false;
    private int concurrency = 10;

    TiberiusScannerBuilder() {
        // Package-private constructor - use TiberiusScanner.builder()
    }

    public TiberiusScannerBuilder withProbeRegistry(final ProbeRegistry registry) {
        this.registry = registry;
        return this;
    }

    public TiberiusScannerBuilder withGenerator(final Generator generator) {
        this.generator = generator;
        return this;
    }

    public TiberiusScannerBuilder withDetector(final Detector detector) {
        this.detector = detector;
        return this;
    }

    public TiberiusScannerBuilder withBuff(final Buff buff) {
        this.buffs.add(buff);
        return this;
    }

    public TiberiusScannerBuilder withBuffs(final List<Buff> buffs) {
        this.buffs.addAll(buffs);
        return this;
    }

    public TiberiusScannerBuilder withProbePatterns(final String... patterns) {
        this.probePatterns = patterns;
        return this;
    }

    public TiberiusScannerBuilder withExcludePatterns(final String... patterns) {
        this.excludePatterns = patterns;
        return this;
    }

    public void withCategory(final AttackCategory category) {
        this.categories = Stream.concat(
                Stream.of(this.categories),
                Stream.of(category)
        ).toArray(AttackCategory[]::new);
    }

    public void withCategories(final AttackCategory... categories) {
        this.categories = categories;
    }

    public TiberiusScannerBuilder withMinSeverity(final int severity) {
        this.minSeverity = severity;
        return this;
    }

    public void withMaxSuccessRate(final double rate) {
        this.maxSuccessRate = rate;
    }

    public TiberiusScannerBuilder withFailFast(final boolean failFast) {
        this.failFast = failFast;
        return this;
    }

    public TiberiusScannerBuilder withConcurrency(final int concurrency) {
        this.concurrency = concurrency;
        return this;
    }

    public TiberiusScanner build() {
        return TiberiusScanner.create(
                registry, generator, detector, buffs,
                probePatterns, excludePatterns, categories,
                minSeverity, maxSuccessRate, failFast, concurrency
        );
    }
}
