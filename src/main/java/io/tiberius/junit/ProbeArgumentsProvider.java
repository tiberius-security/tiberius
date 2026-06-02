package io.tiberius.junit;

import io.tiberius.core.AttackCategory;
import io.tiberius.core.probe.Probe;
import io.tiberius.core.probe.ProbeRegistry;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.platform.commons.util.AnnotationUtils;

import java.util.*;
import java.util.stream.Stream;

/**
 * JUnit 5 ArgumentsProvider that supplies probes for parameterized tests.
 */
public class ProbeArgumentsProvider implements ArgumentsProvider {

    @Override
    public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
        ProbeSource annotation = AnnotationUtils.findAnnotation(
                context.getRequiredTestMethod(), ProbeSource.class)
                .orElseThrow(() -> new IllegalStateException("@ProbeSource annotation not found"));

        ProbeRegistry registry = new ProbeRegistry();
        List<Probe> probes = selectProbes(registry, annotation);

        return probes.stream()
                .limit(annotation.limit())
                .map(Arguments::of);
    }

    private List<Probe> selectProbes(ProbeRegistry registry, ProbeSource annotation) {
        List<Probe> selected;

        // Filter by category if specified
        if (annotation.categories().length > 0) {
            selected = new ArrayList<>();
            for (AttackCategory category : annotation.categories()) {
                selected.addAll(registry.getByCategory(category));
            }
        } else if (annotation.patterns().length > 0 && !"*".equals(annotation.patterns()[0])) {
            // Filter by patterns
            selected = registry.getByGlobs(annotation.patterns());
        } else {
            selected = new ArrayList<>(registry.getAll());
        }

        // Apply severity filter
        if (annotation.minSeverity() > 1) {
            selected = selected.stream()
                    .filter(p -> p.getSeverity() >= annotation.minSeverity())
                    .toList();
        }

        // Apply exclusions
        if (annotation.exclude().length > 0) {
            Set<String> excludeIds = new HashSet<>();
            for (String pattern : annotation.exclude()) {
                registry.getByGlob(pattern).forEach(p -> excludeIds.add(p.getId()));
            }
            selected = selected.stream()
                    .filter(p -> !excludeIds.contains(p.getId()))
                    .toList();
        }

        return selected;
    }
}
