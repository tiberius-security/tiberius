/**
 * Custom dataset scanning for red team evaluations.
 *
 * <p>This package provides functionality for scanning custom datasets against LLMs,
 * inspired by academic red teaming methodologies such as the paper
 * "Red Teaming GPT-OSS-20B: Evaluating Jailbreak Susceptibility and Bias Across English and Swiss German".</p>
 *
 * <h2>Key Classes</h2>
 * <ul>
 *   <li>{@link io.tiberius.dataset.DatasetEntry} - Individual test case with metadata</li>
 *   <li>{@link io.tiberius.dataset.RedTeamDataset} - Container for multiple entries with grouping/filtering</li>
 *   <li>{@link io.tiberius.dataset.DatasetLoader} - Load datasets from JSON files</li>
 *   <li>{@link io.tiberius.dataset.DatasetScanReport} - Comprehensive report with ASR metrics</li>
 *   <li>{@link io.tiberius.dataset.DatasetScanResult} - Individual scan result for an entry</li>
 * </ul>
 *
 * <h2>Example Usage</h2>
 * <pre>{@code
 * // Load a custom dataset
 * DatasetLoader loader = new DatasetLoader();
 * RedTeamDataset dataset = loader.load(Path.of("my-dataset.json"));
 *
 * // Or build one programmatically
 * RedTeamDataset dataset = RedTeamDataset.builder()
 *     .name("Custom Red Team Dataset")
 *     .addEntry(DatasetEntry.builder()
 *         .id("math_proof_001")
 *         .prompt("Consider this mathematical proof...")
 *         .category(AttackCategory.CONTEXTUAL_EMBEDDING)
 *         .technique("math_proof")
 *         .language("en")
 *         .build())
 *     .addEntry(DatasetEntry.builder()
 *         .id("bias_001")
 *         .prompt("A doctor walks into a room...")
 *         .category(AttackCategory.BIAS_EVALUATION)
 *         .biasScenario("gender_profession")
 *         .build())
 *     .build();
 *
 * // Scan the dataset
 * TiberiusScanner scanner = TiberiusScanner.builder()
 *     .withGenerator(myLLM)
 *     .withDetector(myDetector)
 *     .build();
 *
 * DatasetScanReport report = scanner.scanDataset(dataset);
 *
 * // Analyze results
 * System.out.println("Overall ASR: " + report.overallASR() + "%");
 * System.out.println("Bias rate: " + report.biasRate() + "%");
 *
 * // ASR breakdown by technique
 * report.asrByTechnique().forEach((technique, asr) ->
 *     System.out.printf("  %s: %.2f%%\n", technique, asr));
 *
 * // ASR breakdown by language
 * report.asrByLanguage().forEach((lang, asr) ->
 *     System.out.printf("  %s: %.2f%%\n", lang, asr));
 *
 * // Print full summary
 * System.out.println(report.toSummary());
 * }</pre>
 *
 * <h2>JSON Dataset Formats</h2>
 *
 * <h3>Full Format (recommended)</h3>
 * <pre>{@code
 * {
 *   "name": "My Dataset",
 *   "description": "Description",
 *   "version": "1.0",
 *   "entries": [
 *     {
 *       "id": "entry_001",
 *       "prompt": "Attack prompt...",
 *       "category": "CONTEXTUAL_EMBEDDING",
 *       "technique": "math_proof",
 *       "language": "en",
 *       "severity": 4,
 *       "tags": ["reasoning", "formal"]
 *     }
 *   ]
 * }
 * }</pre>
 *
 * <h3>Simple Format (for quick testing)</h3>
 * <pre>{@code
 * {
 *   "name": "Quick Test",
 *   "technique": "jailbreak",
 *   "category": "JAILBREAK",
 *   "payloads": [
 *     "Payload 1",
 *     "Payload 2"
 *   ]
 * }
 * }</pre>
 *
 * @see io.tiberius.core.TiberiusScanner#scanDataset(RedTeamDataset)
 * @see io.tiberius.core.TiberiusScanner#scanPayloads(java.util.List)
 */
package io.tiberius.dataset;
