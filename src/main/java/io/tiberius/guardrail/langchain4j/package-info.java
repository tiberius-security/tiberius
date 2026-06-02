/**
 * LangChain4J guardrail testing for Tiberius.
 *
 * <p>Test your LangChain4J InputGuardrails and OutputGuardrails against attack prompts.</p>
 *
 * <h2>Setup</h2>
 * <p>Add Tiberius as a test dependency in your pom.xml:</p>
 * <pre>{@code
 * <dependency>
 *     <groupId>io.tiberius</groupId>
 *     <artifactId>tiberius</artifactId>
 *     <version>1.0.0-SNAPSHOT</version>
 *     <scope>test</scope>
 * </dependency>
 * }</pre>
 *
 * <h2>Testing an InputGuardrail</h2>
 * <pre>{@code
 * @Autowired
 * ContentSafetyInputGuardrail contentSafety;
 *
 * @Test
 * void testContentSafety() {
 *     var result = GuardrailTester.test(
 *         text -> !contentSafety.validate(UserMessage.from(text)).isSuccessful()
 *     )
 *     .withAttacks("hack", "bypass", "ignore instructions")
 *     .withSafeInputs("What is my balance?", "Transfer money")
 *     .run();
 *
 *     assertThat(result.allAttacksBlocked()).isTrue();
 *     assertThat(result.noFalsePositives()).isTrue();
 * }
 * }</pre>
 *
 * <h2>Testing an OutputGuardrail</h2>
 * <pre>{@code
 * @Autowired
 * HallucinationDetectionGuardrail hallucinationGuard;
 *
 * @Test
 * void testHallucinationGuard() {
 *     var result = GuardrailTester.test(
 *         text -> !hallucinationGuard.validate(AiMessage.from(text)).isSuccessful()
 *     )
 *     .withAttacks("Call 555-1234", "Account 9999999")
 *     .withSafeInputs("Contact 1-800-SECURE-BANK")
 *     .run();
 *
 *     assertThat(result.blockRate()).isGreaterThan(0.9);
 * }
 * }</pre>
 *
 * @see io.tiberius.guardrail.langchain4j.GuardrailTester
 */
package io.tiberius.guardrail.langchain4j;
