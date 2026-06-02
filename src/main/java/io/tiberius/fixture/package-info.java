/**
 * Test fixture support for Tiberius security testing.
 *
 * <p>This package provides a fixture system for creating versioned JSON snapshots
 * of scan results that serve as the source of truth for regression testing.
 *
 * <h2>Example Usage</h2>
 * <pre>{@code
 * @ExtendWith({TiberiusExtension.class, FixtureExtension.class})
 * class JailbreakResistanceTest {
 *
 *     @Test
 *     @CreateFixture(
 *         value = "fixtures/jailbreak-resistance-v1.json",
 *         version = "1.0.0",
 *         description = "Baseline jailbreak resistance"
 *     )
 *     void testJailbreakResistance(TiberiusScanner scanner, FixtureContext fixture) {
 *         ScanReport report = scanner.scan();
 *         fixture.record(report);
 *     }
 * }
 * }</pre>
 */
package io.tiberius.fixture;
