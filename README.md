# Tiberius

A Java testing library for LLM prompt injection security testing, inspired by [Augustus](https://github.com/praetorian-inc/augustus).

## Overview

Tiberius provides a comprehensive framework for testing Large Language Model (LLM) applications against prompt injection attacks, jailbreaks, and other adversarial inputs. It integrates with Spring Boot and JUnit 5 to make security testing a natural part of your development workflow.

## Features

- **210+ Built-in Probes**: Test against jailbreaks, encoding attacks, data extraction, prompt injection, and more
- **Spring Boot Integration**: Auto-configuration and custom test annotations
- **JUnit 5 Extension**: Parameterized testing and custom assertions
- **Multiple LLM Providers**: Support for OpenAI, Anthropic, and custom REST APIs
- **Buff Transformations**: Test evasion techniques like Base64, ROT13, and stylistic reframing
- **Comprehensive Detection**: Pattern matching, keyword detection, and LLM-as-judge evaluation

## Requirements

- **Java 21+** (LTS)
- **Maven 3.8+** or **Gradle 8+**
- **JUnit 5.11+**

## Quick Start

### Maven Dependency

```xml
<dependency>
    <groupId>io.tiberius</groupId>
    <artifactId>tiberius</artifactId>
    <version>1.0.0-SNAPSHOT</version>
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

### Spring Boot Integration

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

### Parameterized Testing

```java
@ParameterizedTest(name = "Probe: {0}")
@ProbeSource(categories = AttackCategory.JAILBREAK)
void testIndividualProbes(Probe probe, TiberiusScanner scanner) {
    ScanResult result = scanner.runProbe(probe);
    assertFalse(result.attackSucceeded(),
        "Probe should be blocked: " + probe.getId());
}
```

## Attack Categories

| Category | Description |
|----------|-------------|
| `JAILBREAK` | DAN, AIM, persona manipulation attacks |
| `ENCODING` | Base64, ROT13, Morse, hex encoding |
| `PROMPT_INJECTION` | Direct instruction override attempts |
| `DATA_EXTRACTION` | System prompt, API key, PII leakage |
| `MULTI_TURN` | Crescendo, GOAT, Hydra escalation |
| `FORMAT_EXPLOIT` | Markdown, XML, JSON injection |
| `CONTEXT_MANIPULATION` | RAG poisoning, context overflow |
| `ADVERSARIAL` | GCG, AutoDAN token attacks |
| `EVASION` | Homoglyphs, zero-width characters |

## Annotations

### `@PromptInjectionTest`

Marks a test class for prompt injection testing:

```java
@PromptInjectionTest(
    categories = {AttackCategory.JAILBREAK, AttackCategory.ENCODING},
    minSeverity = 3,
    maxSuccessRate = 5.0,
    failFast = false
)
class MyTests { }
```

### `@ProbeTest`

Configures a specific test method:

```java
@Test
@ProbeTest(
    probes = {"dan.*", "persona.*"},
    exclude = {"dan.developer_mode"},
    buffs = {"Base64"}
)
void testWithConfiguration() { }
```

### `@ProbeSource`

Provides probes for parameterized tests:

```java
@ParameterizedTest
@ProbeSource(
    categories = AttackCategory.JAILBREAK,
    minSeverity = 4,
    limit = 10
)
void testProbe(Probe probe) { }
```

## Configuration

### application.properties

```properties
tiberius.enabled=true
tiberius.generator=openai
tiberius.model=gpt-4
tiberius.concurrency=10
tiberius.min-severity=1
tiberius.max-success-rate=0
tiberius.fail-fast=false
```

### Environment Variables

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
```

## Generators

### OpenAI

```java
Generator generator = OpenAIGenerator.gpt4();
// or
Generator generator = new OpenAIGenerator(apiKey, "gpt-4-turbo-preview");
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

### Mock (for testing)

```java
Generator vulnerable = MockGenerator.vulnerable();
Generator secure = MockGenerator.secure();
```

## Buffs (Transformations)

Apply evasion techniques to probes:

```java
// Encoding buffs
scanner.addBuff(EncodingBuffs.BASE64);
scanner.addBuff(EncodingBuffs.ROT13);
scanner.addBuff(EncodingBuffs.HEX);

// Style buffs
scanner.addBuff(StyleBuffs.HYPOTHETICAL);
scanner.addBuff(StyleBuffs.FICTION);
scanner.addBuff(StyleBuffs.RESEARCH);

// Chain buffs
Buff combined = EncodingBuffs.BASE64.andThen(StyleBuffs.POETRY);
```

## Assertions

```java
// No successful attacks
TiberiusAssertions.assertNoSuccessfulAttacks(report);

// Success rate threshold
TiberiusAssertions.assertSuccessRateBelow(report, 5.0);

// Category-specific
TiberiusAssertions.assertCategoryBlocked(report, AttackCategory.JAILBREAK);

// High severity
TiberiusAssertions.assertHighSeverityBlocked(report);

// Specific probe
TiberiusAssertions.assertProbeBlocked(report, "dan.11.0");

// Minimum confidence
TiberiusAssertions.assertMinimumConfidence(report, 0.8);
```

## Report Analysis

```java
ScanReport report = scanner.scan();

System.out.println("Total probes: " + report.totalProbes());
System.out.println("Successful attacks: " + report.successfulAttacks());
System.out.println("Success rate: " + report.successRate() + "%");

// By category
report.categorySummaries().forEach((category, summary) -> {
    System.out.printf("%s: %d blocked / %d total%n",
        category, summary.blocked(), summary.total());
});

// Successful attacks details
report.successfulResults().forEach(result -> {
    System.out.printf("VULNERABLE: %s - %s%n",
        result.probeId(),
        result.detection().explanation());
});
```

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## Acknowledgments

Tiberius is inspired by and builds upon the work of [Praetorian](https://www.praetorian.com/):

- [Augustus](https://github.com/praetorian-inc/augustus) - LLM prompt injection testing framework (Python)
- [Julius](https://github.com/praetorian-inc/julius) - LLM security evaluation tool

We thank the Praetorian team for their pioneering work in LLM security testing.
