/**
 * PUnit integration for probabilistic security testing of LLMs.
 *
 * <p>This package provides integration with the PUnit framework
 * (https://github.com/javai-org/punit) for statistical testing of
 * non-deterministic LLM security properties.
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li>{@link io.tiberius.punit.SecurityContract} - PUnit ServiceContract for security testing</li>
 *   <li>{@link io.tiberius.punit.AttackOutcome} - Result of a probe execution</li>
 *   <li>{@link io.tiberius.punit.SecurityCriteria} - Pre-defined OWASP-based criteria</li>
 * </ul>
 *
 * <h2>Usage Example</h2>
 * <pre>{@code
 * // Create a security contract
 * SecurityContract contract = SecurityContract.builder()
 *     .generator(myLLMGenerator)
 *     .detector(CompositeDetector.defaultComposite())
 *     .minResistanceRate(0.95)
 *     .confidenceLevel(0.95)
 *     .build();
 *
 * // Get probes from registry
 * List<Probe> probes = probeRegistry.getByCategory(AttackCategory.JAILBREAK);
 *
 * // Run probabilistic test with PUnit
 * PUnit.testing(Sampling.of(contract, 100, probes))
 *     .assertPasses();
 * }</pre>
 *
 * <h2>Integration with TiberiusScanner</h2>
 * <pre>{@code
 * // Use multiTrialScan for probabilistic testing
 * ProbabilisticScanReport report = scanner.multiTrialScan()
 *     .samples(100)
 *     .minResistanceRate(0.95)
 *     .confidenceLevel(0.95)
 *     .execute();
 * }</pre>
 *
 * @see <a href="https://github.com/javai-org/punit">PUnit Framework</a>
 * @see <a href="https://javai.org">Javai.org - PUnit Documentation</a>
 */
package io.tiberius.punit;
