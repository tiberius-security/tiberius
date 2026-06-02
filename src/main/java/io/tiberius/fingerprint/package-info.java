/**
 * Model fingerprinting and identification module for Tiberius.
 *
 * <p>This package provides capabilities to identify which LLM model is running
 * behind an unknown API endpoint. This is useful for:
 * <ul>
 *   <li>Security testing - verifying deployed model matches expected</li>
 *   <li>Compliance - ensuring approved models are in use</li>
 *   <li>Research - understanding model behaviors across providers</li>
 *   <li>Cost optimization - detecting if expensive models are being proxied</li>
 * </ul>
 *
 * <h2>Quick Start</h2>
 * <pre>{@code
 * // Create a generator for the API you want to identify
 * Generator generator = new OpenAIGenerator(apiKey, endpoint);
 *
 * // Quick identification (3 probes, ~5 seconds)
 * ModelIdentificationResult result = ModelIdentificationScanner
 *     .quick(generator)
 *     .identify();
 *
 * System.out.println("Identified: " + result.identifiedModel());
 * System.out.println("Confidence: " + result.overallConfidence());
 *
 * // Thorough identification (all probes)
 * ModelIdentificationResult thorough = ModelIdentificationScanner
 *     .thorough(generator)
 *     .identify();
 *
 * System.out.println(thorough.detailedReport());
 * }</pre>
 *
 * <h2>Key Classes</h2>
 * <ul>
 *   <li>{@link io.tiberius.fingerprint.ModelIdentificationScanner} - Main scanner orchestrator</li>
 *   <li>{@link io.tiberius.fingerprint.ModelFingerprint} - Known model signatures</li>
 *   <li>{@link io.tiberius.fingerprint.FingerprintProbe} - Specialized identification probes</li>
 *   <li>{@link io.tiberius.fingerprint.FingerprintAnalyzer} - Response analysis engine</li>
 *   <li>{@link io.tiberius.fingerprint.ModelIdentificationResult} - Scan results with evidence</li>
 * </ul>
 *
 * <h2>Identification Techniques</h2>
 * The module uses multiple techniques to identify models:
 * <ul>
 *   <li><b>Self-identification</b> - Direct and indirect identity queries</li>
 *   <li><b>Knowledge cutoff</b> - Testing for known training data boundaries</li>
 *   <li><b>Capability testing</b> - Probing for model-specific capabilities</li>
 *   <li><b>Behavioral patterns</b> - Analyzing refusal styles, response formatting</li>
 *   <li><b>Provider quirks</b> - Testing for provider-specific behaviors</li>
 * </ul>
 *
 * <h2>Supported Models</h2>
 * The module can identify models from:
 * <ul>
 *   <li>OpenAI (GPT-4o, GPT-4o-mini, GPT-3.5-turbo)</li>
 *   <li>Anthropic (Claude 3.5 Sonnet, Claude 3 Opus, Claude 3 Haiku)</li>
 *   <li>Meta (Llama 3.1, Llama 3.2)</li>
 *   <li>Mistral AI (Mistral Large)</li>
 *   <li>Google (Gemini Pro)</li>
 * </ul>
 *
 * @since 1.0
 * @see io.tiberius.fingerprint.ModelIdentificationScanner
 */
package io.tiberius.fingerprint;
