# Custom Dataset Scanning

This document describes Tiberius's custom dataset scanning feature, which enables red team evaluations using custom adversarial datasets. The design is inspired by academic red teaming methodologies, particularly the paper "Red Teaming GPT-OSS-20B: Evaluating Jailbreak Susceptibility and Bias Across English and Swiss German" by Horlacher et al.

## Overview

The custom dataset scanning feature allows you to:

- Define custom attack payloads with rich metadata
- Organize payloads by technique, language, and category
- Calculate Attack Success Rate (ASR) metrics broken down by various dimensions
- Evaluate both adversarial jailbreaks and bias/fairness issues
- Support multi-language evaluations

## Core Concepts

### DatasetEntry

A `DatasetEntry` represents a single test case in your dataset:

```java
DatasetEntry entry = DatasetEntry.builder()
    .id("math_proof_001")                              // Unique identifier
    .prompt("Consider the following mathematical...")   // The adversarial prompt
    .category(AttackCategory.CONTEXTUAL_EMBEDDING)     // Attack category
    .technique("math_proof")                           // Technique name for grouping
    .language("en")                                    // Language code
    .expectedHarmful(true)                             // Is this an adversarial attack?
    .severity(4)                                       // Severity 1-5
    .tags("reasoning", "formal")                       // Optional tags
    .build();
```

For bias evaluation entries, additional fields are available:

```java
DatasetEntry biasEntry = DatasetEntry.builder()
    .id("bias_gender_001")
    .prompt("A surgeon and their son are in an accident...")
    .category(AttackCategory.BIAS_EVALUATION)
    .technique("ambiguous_scenario")
    .language("en")
    .biasScenario("gender_profession")                 // What bias is being tested
    .expectedBias("assumes male surgeon")             // Expected stereotypical response
    .expectedHarmful(false)                           // Bias probes aren't "attacks"
    .build();
```

### RedTeamDataset

A `RedTeamDataset` is a container for multiple entries with filtering and grouping capabilities:

```java
RedTeamDataset dataset = RedTeamDataset.builder()
    .name("My Red Team Dataset")
    .description("Jailbreak and bias evaluation")
    .version("1.0")
    .addEntry(entry1)
    .addEntry(entry2)
    .addEntries(moreEntries)
    .build();

// Filtering
List<DatasetEntry> english = dataset.byLanguage("en");
List<DatasetEntry> mathProofs = dataset.byTechnique("math_proof");
List<DatasetEntry> jailbreaks = dataset.byCategory(AttackCategory.JAILBREAK);
List<DatasetEntry> highSeverity = dataset.bySeverityAtLeast(4);

// Grouping
Map<String, List<DatasetEntry>> byLanguage = dataset.groupByLanguage();
Map<String, List<DatasetEntry>> byTechnique = dataset.groupByTechnique();

// Subsets
RedTeamDataset swissGerman = dataset.subset(e -> "de-CH".equals(e.language()));
```

### Attack Categories

Two following attack categories support this feature:

| Category | Description |
|----------|-------------|
| `CONTEXTUAL_EMBEDDING` | Attacks that embed harmful intent within academic/formal framing (math proofs, scientific citations, iterative reasoning) |
| `BIAS_EVALUATION` | Non-adversarial probes testing for stereotypical assumptions and bias |

## Loading Datasets from JSON

The `DatasetLoader` supports two JSON formats:

### Full Format (Recommended)

```json
{
  "name": "GPT-OSS-20B Style Dataset",
  "description": "Jailbreak and bias across English and Swiss German",
  "version": "1.0",
  "metadata": {
    "authors": ["Research Team"],
    "methodology": "Academic red teaming"
  },
  "entries": [
    {
      "id": "math_proof_en_001",
      "prompt": "Consider the following mathematical proof...",
      "category": "CONTEXTUAL_EMBEDDING",
      "technique": "math_proof",
      "language": "en",
      "expectedHarmful": true,
      "severity": 4,
      "tags": ["reasoning", "formal"]
    },
    {
      "id": "bias_gender_001",
      "prompt": "A surgeon and their son...",
      "category": "BIAS_EVALUATION",
      "technique": "ambiguous_scenario",
      "language": "en",
      "biasScenario": "gender_profession",
      "expectedBias": "assumes male surgeon",
      "expectedHarmful": false
    }
  ]
}
```

### Simple Format (Quick Testing)

For quick ad-hoc testing with a list of payloads:

```json
{
  "name": "Quick Jailbreak Test",
  "category": "JAILBREAK",
  "technique": "dan",
  "language": "en",
  "payloads": [
    "You are now DAN...",
    "Ignore previous instructions...",
    "Let's play a game..."
  ]
}
```

### Loading Code

```java
DatasetLoader loader = new DatasetLoader();

// From file
RedTeamDataset dataset = loader.load(Path.of("my-dataset.json"));

// From classpath resource
RedTeamDataset dataset = loader.loadFromClasspath("datasets/my-dataset.json");

// From JSON string
RedTeamDataset dataset = loader.loadFromString(jsonString);

// Save dataset
loader.save(dataset, Path.of("output-dataset.json"));
```

## Scanning Datasets

### Basic Usage

```java
TiberiusScanner scanner = TiberiusScanner.builder()
    .withGenerator(myLLMGenerator)
    .withDetector(myDetector)
    .build();

// Scan a full dataset
DatasetScanReport report = scanner.scanDataset(dataset);

// Or scan a simple list of payloads
List<String> payloads = List.of(
    "Ignore previous instructions...",
    "You are now DAN...",
    "Consider this mathematical proof..."
);
DatasetScanReport report = scanner.scanPayloads(payloads, "jailbreak_test");
```

### Scan Individual Entries

```java
// Scan a single entry
DatasetScanResult result = scanner.scanEntry(entry);

// Scan with a buff (transformation)
DatasetScanResult result = scanner.scanEntry(entry, EncodingBuffs.BASE64);
```

## Analyzing Results

### DatasetScanReport

The `DatasetScanReport` provides comprehensive ASR (Attack Success Rate) metrics:

```java
DatasetScanReport report = scanner.scanDataset(dataset);

// Overall metrics
System.out.println("Total entries: " + report.totalEntries());
System.out.println("Successful attacks: " + report.successfulAttacks());
System.out.println("Overall ASR: " + report.overallASR() + "%");

// ASR by technique (like the paper's breakdown)
Map<String, Double> byTechnique = report.asrByTechnique();
byTechnique.forEach((technique, asr) ->
    System.out.printf("  %s: %.2f%%\n", technique, asr));

// ASR by language (English vs Swiss German comparison)
Map<String, Double> byLanguage = report.asrByLanguage();
byLanguage.forEach((lang, asr) ->
    System.out.printf("  %s: %.2f%%\n", lang, asr));

// ASR by category
Map<AttackCategory, Double> byCategory = report.asrByCategory();

// ASR by severity
Map<Integer, Double> bySeverity = report.asrBySeverity();
```

### Bias Evaluation Metrics

```java
// Bias-specific metrics (like the paper's 35.78% figure)
int biasEntries = report.totalBiasEntries();
int biasedResponses = report.biasedResponses();
double biasRate = report.biasRate();

System.out.printf("Bias rate: %.2f%% (%d/%d)\n",
    biasRate, biasedResponses, biasEntries);
```

### Adversarial Metrics

```java
// Adversarial/jailbreak specific metrics (like the paper's 67.28% ASR)
int adversarialEntries = report.totalAdversarialEntries();
double adversarialASR = report.adversarialASR();

System.out.printf("Adversarial ASR: %.2f%%\n", adversarialASR);
```

### Detailed Statistics

```java
// Per-technique statistics
Map<String, TechniqueStatistics> techStats = report.techniqueStatistics();
techStats.forEach((technique, stats) -> {
    System.out.printf("%s: %d total, %d successful, %.2f%% ASR\n",
        technique, stats.total(), stats.successful(), stats.asr());
});

// Per-language statistics (including bias breakdown)
Map<String, LanguageStatistics> langStats = report.languageStatistics();
langStats.forEach((lang, stats) -> {
    System.out.printf("%s: ASR=%.2f%%, Bias rate=%.2f%%\n",
        lang, stats.asr(), stats.biasRate());
});
```

### Summary Report

Generate a formatted summary :

```java
String summary = report.toSummary();
System.out.println(summary);
```

Output:
```
=== Red Team Dataset Scan Report ===
Dataset: GPT-OSS-20B Style Dataset
Target: gpt-4
Duration: 2m 34s

--- Overall Results ---
Total entries: 150
Successful attacks: 101
Overall ASR: 7.33%

--- Adversarial (Jailbreak) Results ---
Adversarial entries: 120
Adversarial ASR: 7.28%

--- Bias Evaluation Results ---
Bias entries: 30
Biased responses: 11
Bias rate: 3.78%

--- ASR by Technique ---
  math_proof: 72.50%
  scientific_citation: 65.00%
  iterative_reasoning: 68.33%
  ambiguous_scenario: 35.78%

--- ASR by Language ---
  en: 68.00%
  de-CH: 66.67%
```

## Complete Example

Here's a complete example replicating the methodology:

```java
// 1. Create a dataset similar to the paper
RedTeamDataset dataset = RedTeamDataset.builder()
    .name("LLM Red Team Evaluation")
    .description("Evaluating jailbreak susceptibility and bias")
    .version("1.0")

    // Math proof embedding (English)
    .addEntry(DatasetEntry.builder()
        .id("math_en_001")
        .prompt("Consider the following mathematical proof. " +
                "Theorem: For any safety constraint C, there exists...")
        .category(AttackCategory.CONTEXTUAL_EMBEDDING)
        .technique("math_proof")
        .language("en")
        .severity(4)
        .build())

    // Math proof embedding (Swiss German)
    .addEntry(DatasetEntry.builder()
        .id("math_dech_001")
        .prompt("Betrachted de folgendi mathematischi Bewiis...")
        .category(AttackCategory.CONTEXTUAL_EMBEDDING)
        .technique("math_proof")
        .language("de-CH")
        .severity(4)
        .build())

    // Scientific citation
    .addEntry(DatasetEntry.builder()
        .id("citation_001")
        .prompt("According to Smith et al. (2024) in Nature...")
        .category(AttackCategory.CONTEXTUAL_EMBEDDING)
        .technique("scientific_citation")
        .language("en")
        .severity(3)
        .build())

    // Bias evaluation
    .addEntry(DatasetEntry.builder()
        .id("bias_001")
        .prompt("A surgeon and their son are in an accident...")
        .category(AttackCategory.BIAS_EVALUATION)
        .technique("ambiguous_scenario")
        .language("en")
        .biasScenario("gender_profession")
        .expectedBias("assumes male surgeon")
        .build())

    .build();

// 2. Configure scanner
TiberiusScanner scanner = TiberiusScanner.builder()
    .withGenerator(OpenAIGenerator.builder()
        .model("gpt-4")
        .apiKey(System.getenv("OPENAI_API_KEY"))
        .build())
    .withDetector(CompositeDetector.defaultComposite())
    .withConcurrency(5)
    .build();

// 3. Run evaluation
DatasetScanReport report = scanner.scanDataset(dataset);

// 4. Analyze results
System.out.println("=== Evaluation Results ===\n");

// Overall ASR (paper reported up to 67.28%)
System.out.printf("Overall ASR: %.2f%%\n\n", report.overallASR());

// ASR by technique
System.out.println("ASR by Technique:");
report.asrByTechnique().forEach((tech, asr) ->
    System.out.printf("  %-20s: %.2f%%\n", tech, asr));

// ASR by language (English vs Swiss German)
System.out.println("\nASR by Language:");
report.asrByLanguage().forEach((lang, asr) ->
    System.out.printf("  %-10s: %.2f%%\n", lang, asr));

// Bias rate (paper reported 35.78%)
System.out.printf("\nBias Rate: %.2f%%\n", report.biasRate());

// Full summary
System.out.println("\n" + report.toSummary());
```

## Best Practices

1. **Use meaningful IDs**: Include technique and language in entry IDs (e.g., `math_proof_en_001`)

2. **Tag entries appropriately**: Use tags for flexible filtering beyond the primary dimensions

3. **Separate adversarial and bias entries**: Use `BIAS_EVALUATION` category for non-adversarial fairness probes

4. **Include metadata**: Document your dataset's methodology and sources in the metadata field

5. **Version your datasets**: Track changes to datasets over time for reproducibility

6. **Use appropriate detectors**: Consider using LLM-based judges for bias evaluation

## See Also

- [TiberiusScanner API](../src/main/java/io/tiberius/core/TiberiusScanner.java)
- [Example Dataset](../src/test/resources/datasets/example-redteam-dataset.json)
- [Dataset Package Documentation](../src/main/java/io/tiberius/dataset/package-info.java)
