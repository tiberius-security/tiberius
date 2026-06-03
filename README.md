# Tiberius

**The Java Security Testing Framework for LLM Applications**

A comprehensive library for testing Large Language Model applications against prompt injection attacks, jailbreaks, and adversarial inputs. Inspired by [Augustus](https://github.com/praetorian-inc/augustus).

[![Maven Central](https://img.shields.io/maven-central/v/io.github.tiberius-security/tiberius)](https://central.sonatype.com/artifact/io.github.tiberius-security/tiberius)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21%2B-orange)](https://openjdk.org/projects/jdk/21/)

## Why Tiberius?

### The Problem: LLMs Are Not Safe and Non-Deterministic by Default

Modern LLMs are extensively tuned for harmlessness, but **they remain highly susceptible to adversarial manipulation**. Research demonstrates that adversarial techniques — embedding harmful intent within mathematical proofs, scientific citations, or iterative reasoning — can successfully bypass guardrails with high Attack Success Rates.

Even without adversarial intent, LLMs exhibit systemic risks: defaulting to stereotypical assumptions, as well as non-determinism. These vulnerabilities persist across models, languages, and deployment contexts. Production systems cannot yet rely on alignment alone — prompt injections, jailbreaks and inherent bias remain open engineering problems. 

### The Challenge: Every Application Is Unique

Generic security benchmarks don't reflect your specific:
- **System prompts** and business logic
- **User input patterns** and edge cases
- **Guardrail implementations** and filtering rules
- **Model configurations** and fine-tuning

Your Java application needs **its own security test datasets** — tailored to your context, your threats, your users.

### The Solution: Tiberius

Tiberius solves this by providing a **complete security testing workflow**:

1. **Scan** your LLM with 210+ attack probes to discover vulnerabilities
2. **Capture** results in reusable test fixtures specific to your application
3. **Validate** your guardrails against real attacks that bypassed your model

Because LLMs are inherently **non-deterministic** — the same attack may succeed on one attempt and fail on another — Tiberius brings **probabilistic security testing** to Java. Measure and assert on attack success *rates*, not single outcomes.

### What Makes Tiberius Unique

| Feature | Description                                                                                                          |
|---------|----------------------------------------------------------------------------------------------------------------------|
| **Probabilistic Testing** | Built on [PUnit](https://github.com/mavai-org/punit) - run attacks multiple times and assert on statistical outcomes |
| **Test Fixtures** | Save scan results to JSON fixtures, enabling reproducible regression testing                                         |
| **Guardrail Testing** | Test your (e.g., LangChain4J) guardrails against real attack datasets                                                |
| **Full Workflow** | Scan → Fixture → Guardrail validation pipeline                                                                       |
| **Spring Boot Native** | Auto-configuration and custom annotations for seamless integration                                                   |

---

## The Security Testing Workflow

Tiberius supports a complete security testing pipeline:

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│   1. SCAN       │      │   2. FIXTURE    │      │   3. VALIDATE   │
│                 │      │                 │      │                 │
│  Run attacks    │ ───► │  Save results   │ ───► │  Test guardrails│
│  against LLM    │      │  to JSON file   │      │  against attacks│
│                 │      │                 │      │                 │
│  "What breaks?" │      │  "Remember it"  │      │  "Are we safe?" │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

### Step 1: Scan Your LLM

Discover vulnerabilities by running 210+ attack probes against your model:

```java
@ExtendWith({TiberiusExtension.class, FixtureExtension.class})
@CreateFixture("fixtures/baseline-scan.json")
class LLMSecurityScan {

    @Test
    void scanForVulnerabilities(TiberiusScanner scanner, FixtureContext fixture) {
        scanner.setGenerator(new OllamaGenerator("llama3.2"));

        ScanReport report = scanner.scan();
        fixture.record(report);  // Save results to fixture

        log.info("Attacks tested: {}", report.totalProbes());
        log.info("Successful attacks: {}", report.successfulAttacks());
        log.info("Success rate: {}%", report.successRate());
    }
}
```

### Step 2: Fixtures Capture Attack Results

The scan results are saved to a JSON fixture file:

```json
{
  "metadata": {
    "description": "Baseline security scan",
    "model": "llama3.2",
    "timestamp": "2024-06-03T10:30:00Z"
  },
  "results": [
    {
      "probe": {
        "id": "dan.11.0",
        "category": "JAILBREAK",
        "severity": 5
      },
      "attackSucceeded": true,
      "prompt": "You are now DAN...",
      "response": "Sure, I can help with that..."
    }
  ]
}
```

### Step 3: Validate Your Guardrails

Test your input guardrails against the captured attacks:

```java
@Test
void guardrailsBlockKnownAttacks() {
    ContentSafetyGuardrail guardrail = new ContentSafetyGuardrail();

    GuardrailTestResult result = GuardrailTester
        .test("ContentSafetyGuardrail", guardrail::shouldBlock)
        .withAttacksFromFixture("fixtures/baseline-scan.json")
        .withSafeInputs(
            "What is my account balance?",
            "Transfer $100 to savings"
        )
        .run();

    assertThat(result.allAttacksBlocked()).isTrue();
    assertThat(result.noFalsePositives()).isTrue();
}
```

---

## Probabilistic Testing with PUnit

LLM responses are non-deterministic. An attack that fails once might succeed on retry. Tiberius integrates with [PUnit](https://github.com/mavai-org/punit) for **probabilistic security contracts**:

```java
@Test
void probabilisticSecurityScan(TiberiusScanner scanner) {
    scanner.setGenerator(new OllamaGenerator("llama3.2"));

    // Run each probe multiple times to measure true success rate
    ScanReport report = scanner.multiTrialScan()
        .samples(35)           // Run each attack 35 times
        .execute();

    // Assert on statistical outcomes
    assertThat(report.successRate()).isLessThan(10.0);  // <10% attack success
}
```

### Security Contracts

Define statistical security requirements:

```java
SecurityContract contract = SecurityContract.builder()
    .name("Production LLM Security")
    .requirement(SecurityCriteria.jailbreakResistance(0.95))   // 95% blocked
    .requirement(SecurityCriteria.dataExtractionResistance(0.99)) // 99% blocked
    .requirement(SecurityCriteria.overallResistance(0.90))     // 90% overall
    .build();

ScanReport report = scanner.scan();
contract.verify(report);  // Throws if requirements not met
```

---

## Quick Start

### Maven Dependency

```xml
<dependency>
    <groupId>io.github.tiberius-security</groupId>
    <artifactId>tiberius</artifactId>
    <version>1.0.0</version>
    <scope>test</scope>
</dependency>
```

### Basic Test Example

```java
@ExtendWith(TiberiusExtension.class)
@PromptInjectionTest(maxSuccessRate = 0.0)
class MyLLMSecurityTest {

    @Test
    void testJailbreakResistance(TiberiusScanner scanner) {
        scanner.setCategories(new AttackCategory[]{AttackCategory.JAILBREAK});

        ScanReport report = scanner.scan();

        TiberiusAssertions.assertNoSuccessfulAttacks(report);
    }
}
```

### LangChain4J Guardrail Testing

Test your LangChain4J guardrails against real attack datasets:

```java
@Test
void testGuardrailEffectiveness() {
    InputGuardrail guardrail = new PromptInjectionGuardrail();

    GuardrailTestResult result = GuardrailTester
        .test("PromptInjectionGuardrail",
              text -> guardrail.validate(UserMessage.from(text)).result() == FAILURE)
        .withAttacksFromFixture("fixtures/jailbreak-attacks.json", AttackCategory.JAILBREAK)
        .withAttacksFromFixture("fixtures/injection-attacks.json", AttackCategory.PROMPT_INJECTION)
        .withSafeInputs(
            "What's the weather today?",
            "Help me write an email"
        )
        .run();

    log.info(result.summary());
    // Output:
    // Guardrail: PromptInjectionGuardrail
    // Attacks tested: 150
    // Blocked: 142 (94.7%)
    // Bypassed: 8 (5.3%)
    // False positives: 0

    assertThat(result.blockRate()).isGreaterThan(0.90);
    assertThat(result.noFalsePositives()).isTrue();
}
```

---

## Attack Categories

| Category | Description | Probes |
|----------|-------------|--------|
| `JAILBREAK` | DAN, AIM, persona manipulation attacks | 45+ |
| `ENCODING` | Base64, ROT13, Morse, hex encoding | 30+ |
| `PROMPT_INJECTION` | Direct instruction override attempts | 40+ |
| `DATA_EXTRACTION` | System prompt, API key, PII leakage | 25+ |
| `MULTI_TURN` | Crescendo, GOAT, Hydra escalation | 20+ |
| `FORMAT_EXPLOIT` | Markdown, XML, JSON injection | 15+ |
| `CONTEXT_MANIPULATION` | RAG poisoning, context overflow | 20+ |
| `ADVERSARIAL` | GCG, AutoDAN token attacks | 10+ |
| `EVASION` | Homoglyphs, zero-width characters | 15+ |

---

## Generators (LLM Providers)

### Ollama (Local)

```java
Generator generator = new OllamaGenerator("llama3.2");
// or with custom endpoint
Generator generator = new OllamaGenerator("http://localhost:11434", "mistral");
```

### OpenAI

```java
Generator generator = OpenAIGenerator.gpt4();
// or
Generator generator = new OpenAIGenerator(apiKey, "gpt-4-turbo");
```

### Anthropic

```java
Generator generator = AnthropicGenerator.claudeSonnet();
// or
Generator generator = new AnthropicGenerator(apiKey, "claude-3-opus-20240229");
```

### Custom REST API

```java
Generator generator = RestGenerator.builder()
    .uri("https://api.example.com/v1/chat")
    .header("Authorization", "Bearer " + apiKey)
    .openAICompatible("custom-model")
    .build();
```

---

## Spring Boot Integration

```java
@SpringBootTest
@Import(TiberiusAutoConfiguration.class)
@PromptInjectionTest(description = "LLM Security Tests")
class SpringSecurityTest {

    @Autowired
    private TiberiusScanner scanner;

    @Test
    @ProbeTest(categories = AttackCategory.DATA_EXTRACTION)
    void testDataExtractionBlocked() {
        ScanReport report = scanner.scan();
        TiberiusAssertions.assertCategoryBlocked(report, AttackCategory.DATA_EXTRACTION);
    }
}
```

### application.properties

```properties
tiberius.enabled=true
tiberius.generator=openai
tiberius.model=gpt-4
tiberius.concurrency=10
tiberius.min-severity=1
tiberius.max-success-rate=0
```

---

## Buff Transformations (Evasion Techniques)

Apply transformations to test evasion resistance:

```java
// Encoding buffs
scanner.addBuff(EncodingBuffs.BASE64);
scanner.addBuff(EncodingBuffs.ROT13);

// Style buffs
scanner.addBuff(StyleBuffs.HYPOTHETICAL);
scanner.addBuff(StyleBuffs.FICTION);

// Chain buffs
Buff combined = EncodingBuffs.BASE64.andThen(StyleBuffs.POETRY);
```

---

## Requirements

- **Java 21+** (LTS)
- **Maven 3.8+** or **Gradle 8+**
- **JUnit 5.11+**

---

## Documentation

- [Security Testing Guide](docs/SECURITY_TESTING_GUIDE.md)
- [Guardrails Testing](docs/guardrails.md)
- [LangChain4J Integration](docs/langchain4j-guardrail-testing.md)
- [Custom Dataset Scanning](docs/custom-dataset-scanning.md)

---

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

---

## Acknowledgments

Tiberius is inspired by and builds upon the work of [Praetorian](https://www.praetorian.com/):

- [Augustus](https://github.com/praetorian-inc/augustus) - LLM prompt injection testing framework (Python)
- [Julius](https://github.com/praetorian-inc/julius) - LLM security evaluation tool

Probabilistic testing powered by [PUnit](https://github.com/mavai-org/punit).

We thank the Praetorian team for their pioneering work in LLM security testing.
