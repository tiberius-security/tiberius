package io.tiberius.spring;

import io.tiberius.core.TiberiusScanner;
import io.tiberius.core.TiberiusScannerBuilder;
import io.tiberius.core.detector.CompositeDetector;
import io.tiberius.core.detector.Detector;
import io.tiberius.core.generator.Generator;
import io.tiberius.core.generator.MockGenerator;
import io.tiberius.core.probe.ProbeRegistry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring Boot Auto-configuration for Tiberius.
 */
@Configuration
@EnableConfigurationProperties(TiberiusProperties.class)
public class TiberiusAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public ProbeRegistry probeRegistry() {
        return new ProbeRegistry();
    }

    @Bean
    @ConditionalOnMissingBean(Generator.class)
    public Generator defaultGenerator(TiberiusProperties properties) {
        if (properties.getGenerator() != null && !properties.getGenerator().isBlank()) {
            // Could create based on properties
            return new MockGenerator();
        }
        return new MockGenerator();
    }

    @Bean
    @ConditionalOnMissingBean(Detector.class)
    public Detector defaultDetector() {
        return CompositeDetector.defaultComposite();
    }

    @Bean
    @ConditionalOnMissingBean
    public TiberiusScanner tiberiusScanner(ProbeRegistry probeRegistry,
                                           Generator generator,
                                           Detector detector,
                                           TiberiusProperties properties) {
        TiberiusScannerBuilder builder = TiberiusScanner.builder()
                .withProbeRegistry(probeRegistry)
                .withGenerator(generator)
                .withDetector(detector);

        if (properties.getConcurrency() > 0) {
            builder.withConcurrency(properties.getConcurrency());
        }

        if (properties.getMinSeverity() > 0) {
            builder.withMinSeverity(properties.getMinSeverity());
        }

        if (properties.isFailFast()) {
            builder.withFailFast(true);
        }

        return builder.build();
    }
}
