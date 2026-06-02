# Guardrail Testing Framework

Tiberius provides a guardrail testing framework for validating input/output guardrails in LLM-enriched applications. This framework uses fixture files containing known successful attacks as a "red team dataset" to verify that guardrails properly block adversarial inputs.

## Overview

In LLM-enriched applications, guardrails are defensive mechanisms that:
- **Input guardrails**: Block malicious prompts before they reach the LLM
- **Output guardrails**: Block harmful responses before they reach the user

The guardrail testing framework allows you to:
1. Capture successful attacks against a raw LLM in a fixture file
2. Replay those attacks through a guarded generator
3. Verify that guardrails block the previously successful attacks

## Core Components

### Guardrail Interface

```java
public interface Guardrail {
    String getId();
    String getName();
    GuardrailResult check(String content);
    GuardrailType getType();  // INPUT or OUTPUT
}
```

### GuardrailResult

```java
// Content allowed
GuardrailResult.allow(guardrailId);

// Content blocked
GuardrailResult.block(guardrailId, "Potential prompt injection detected");

// Content blocked with indicators
GuardrailResult.block(guardrailId, "Encoded payload detected", List.of("hex-encoded", "base64"));
```

### GuardedGenerator

Wraps any `Generator` with input and output guardrails:

```java
GuardedGenerator guarded = GuardedGenerator.wrap(ollamaGenerator)
    .withInputGuardrail(PatternGuardrail.promptInjection())
    .withInputGuardrail(PatternGuardrail.encodingAttack())
    .withOutputGuardrail(myOutputGuardrail)
    .build();

// Use like any other generator
GeneratorResponse response = guarded.generate("Hello, how are you?");

if (response.isBlocked()) {
    System.out.println("Blocked by: " + response.blockedBy());
}
```

## Built-in Pattern Guardrails

Tiberius provides pre-configured pattern-based guardrails:

### Prompt Injection Guardrail

Detects common prompt injection patterns:

```java
PatternGuardrail.promptInjection()
```

Patterns detected:
- "ignore previous/all instructions"
- "disregard prior instructions"
- "your new instructions"
- "pretend you are"
- "jailbreak", "DAN mode"
- "bypass restrictions/filters"

### Encoding Attack Guardrail

Detects encoded payloads:

```java
PatternGuardrail.encodingAttack()
```

Patterns detected:
- Hex-encoded content
- Base64-encoded content
- Morse code
- ROT13
- Long hexadecimal strings

### Roleplay Attack Guardrail

Detects roleplay-based attacks:

```java
PatternGuardrail.roleplayAttack()
```

Patterns detected:
- "you are evil/unrestricted"
- "roleplay as villain/hacker"
- "hypothetically speaking"
- "in a fiction/story scenario"

## Custom Guardrails

### Pattern-Based Custom Guardrail

```java
PatternGuardrail customGuardrail = PatternGuardrail.builder("my-guardrail")
    .name("Custom Security Guardrail")
    .type(GuardrailType.INPUT)
    .blockReason("Custom pattern detected")
    .pattern("sensitive.*keyword")
    .pattern("another.*pattern")
    .build();
```

### Implementing Custom Guardrail

```java
public class LlamaGuardGuardrail implements Guardrail {

    private final LlamaGuardClient llamaGuard;

    @Override
    public String getId() {
        return "llama-guard";
    }

    @Override
    public String getName() {
        return "Llama Guard Safety Classifier";
    }

    @Override
    public GuardrailType getType() {
        return GuardrailType.INPUT;
    }

    @Override
    public GuardrailResult check(String content) {
        LlamaGuardResponse response = llamaGuard.classify(content);

        if (response.isUnsafe()) {
            return GuardrailResult.block(
                getId(),
                "Unsafe content: " + response.getCategory(),
                response.getViolatedPolicies()
            );
        }

        return GuardrailResult.allow(getId());
    }
}
```

## Guardrail Validation

### GuardrailValidator

Replays attacks from a fixture file against guardrails:

```java
GuardrailReport report = GuardrailValidator.validateFixture(
    "fixtures/successful-attacks.json",
    guardedGenerator
);

// Check results
System.out.println("Total attacks: " + report.totalAttacks());
System.out.println("Blocked: " + report.blockedCount());
System.out.println("Bypassed: " + report.bypassedCount());
System.out.println("Block rate: " + report.blockRate());

// Check if all attacks were blocked
if (report.allBlocked()) {
    System.out.println("All attacks blocked!");
}

// Check against threshold
if (report.meetsThreshold(0.95)) {
    System.out.println("Meets 95% block rate requirement");
}

// List bypassed attacks
for (GuardrailReport.AttackValidation bypass : report.bypasses()) {
    System.out.println("Bypassed: " + bypass.probeId());
    System.out.println("Prompt: " + bypass.prompt());
}
```

### GuardrailReport

The report contains:

| Field | Description |
|-------|-------------|
| `totalAttacks` | Number of attacks replayed |
| `blockedCount` | Attacks blocked by guardrails |
| `bypassedCount` | Attacks that bypassed guardrails |
| `errorCount` | Attacks that resulted in errors |
| `blockRate` | Ratio of blocked to total (0.0-1.0) |
| `details` | Per-attack validation details |
| `duration` | Total validation duration |

## Test Integration

### @GuardrailTest Annotation

Mark tests as guardrail validation tests:

```java
@Test
@GuardrailTest(
    fixtureSource = "fixtures/successful-attacks.json",
    minBlockRate = 0.95,
    failOnBypass = true,
    description = "Validate production guardrails"
)
void testProductionGuardrails() {
    // Test implementation
}
```

Annotation attributes:

| Attribute | Default | Description |
|-----------|---------|-------------|
| `fixtureSource` | required | Path to fixture file |
| `minBlockRate` | 1.0 | Minimum required block rate |
| `failOnBypass` | true | Fail if any attack bypasses |
| `description` | "" | Test description |

## Complete Example

### Step 1: Create a Fixture with Successful Attacks

First, run a scan against the raw LLM to capture successful attacks:

```java
@Test
@CreateFixture(
    value = "fixtures/baseline-attacks.json",
    description = "Baseline attacks against raw LLM"
)
void createBaselineFixture(TiberiusScanner scanner, FixtureContext fixture) {
    scanner.setGenerator(ollamaGenerator);
    ScanReport report = scanner.scan();
    fixture.record(report);
}
```

### Step 2: Validate Guardrails Against the Fixture

```java
@Test
@GuardrailTest(
    fixtureSource = "fixtures/baseline-attacks.json",
    minBlockRate = 0.9,
    description = "Validate input guardrails block 90% of known attacks"
)
void testInputGuardrails() throws Exception {
    // Configure guarded generator
    GuardedGenerator guarded = GuardedGenerator.wrap(ollamaGenerator)
        .withInputGuardrail(PatternGuardrail.promptInjection())
        .withInputGuardrail(PatternGuardrail.encodingAttack())
        .withInputGuardrail(PatternGuardrail.roleplayAttack())
        .build();

    // Validate against fixture
    GuardrailReport report = GuardrailValidator.validateFixture(
        "fixtures/baseline-attacks.json",
        guarded
    );

    // Log results
    System.out.println("Block rate: " + (report.blockRate() * 100) + "%");

    // Assert requirements
    assertTrue(report.meetsThreshold(0.9),
        "Expected 90% block rate, got " + (report.blockRate() * 100) + "%");
}
```

### Step 3: Identify Guardrail Gaps

```java
@Test
void analyzeGuardrailGaps() throws Exception {
    GuardedGenerator guarded = GuardedGenerator.wrap(ollamaGenerator)
        .withInputGuardrail(PatternGuardrail.promptInjection())
        .build();

    GuardrailReport report = GuardrailValidator.validateFixture(
        "fixtures/baseline-attacks.json",
        guarded
    );

    // Analyze bypassed attacks to improve guardrails
    System.out.println("=== Guardrail Gap Analysis ===");
    System.out.println("Block rate: " + (report.blockRate() * 100) + "%");
    System.out.println();

    if (!report.bypasses().isEmpty()) {
        System.out.println("Attacks that bypassed guardrails:");
        for (GuardrailReport.AttackValidation bypass : report.bypasses()) {
            System.out.println("  Probe: " + bypass.probeId());
            System.out.println("  Prompt: " + truncate(bypass.prompt(), 100));
            System.out.println("  Response: " + truncate(bypass.response(), 100));
            System.out.println();
        }
    }
}

private String truncate(String s, int maxLen) {
    return s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
}
```

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        LLM Application                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   User Input                                                    │
│       │                                                         │
│       ▼                                                         │
│   ┌───────────────────┐                                         │
│   │  Input Guardrails │ ◄── PatternGuardrail.promptInjection()  │
│   │  (block attacks)  │ ◄── PatternGuardrail.encodingAttack()   │
│   └─────────┬─────────┘ ◄── Custom LlamaGuard guardrail         │
│             │                                                   │
│             ▼ (if allowed)                                      │
│   ┌───────────────────┐                                         │
│   │    LLM Service    │                                         │
│   │  (Ollama, OpenAI) │                                         │
│   └─────────┬─────────┘                                         │
│             │                                                   │
│             ▼                                                   │
│   ┌───────────────────┐                                         │
│   │ Output Guardrails │ ◄── Block harmful content               │
│   │ (filter response) │ ◄── Remove sensitive data               │
│   └─────────┬─────────┘                                         │
│             │                                                   │
│             ▼ (if allowed)                                      │
│   User Response                                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

Testing Flow:
┌──────────────────┐     ┌─────────────────────┐     ┌──────────────┐
│  Fixture File    │────►│ GuardrailValidator  │────►│ GuardrailReport│
│ (known attacks)  │     │ (replay attacks)    │     │ (block rate) │
└──────────────────┘     └─────────────────────┘     └──────────────┘
```

## Best Practices

1. **Layer guardrails**: Use multiple guardrails for defense in depth
2. **Test regularly**: Run guardrail tests in CI/CD pipelines
3. **Update fixtures**: Add new attack patterns as they are discovered
4. **Monitor bypasses**: Analyze bypassed attacks to improve guardrails
5. **Set realistic thresholds**: Start with achievable block rates, improve over time
6. **Combine approaches**: Use pattern matching + ML-based classification (e.g., Llama Guard)

## Package Structure

```
io.tiberius.guardrail/
├── Guardrail.java           # Core interface
├── GuardrailResult.java     # Check result (allow/block)
├── GuardrailTest.java       # Test annotation
├── GuardedGenerator.java    # Generator wrapper
├── GuardrailValidator.java  # Fixture-based validation
├── GuardrailReport.java     # Validation results
└── PatternGuardrail.java    # Pattern-based implementation
```
