package io.tiberius.fingerprint;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analyzes LLM responses to identify model fingerprints.
 * Uses pattern matching, response style analysis, and heuristics.
 */
public final class FingerprintAnalyzer {

    private final List<ModelFingerprint> candidateModels;
    private final AnalysisConfig config;

    /**
     * Configuration for analysis.
     */
    public record AnalysisConfig(
            boolean caseInsensitive,
            int minPatternLength,
            double exactMatchMultiplier,
            double partialMatchMultiplier,
            boolean analyzeStyle,
            boolean analyzeLength
    ) {
        public static AnalysisConfig defaults() {
            return new AnalysisConfig(true, 2, 1.5, 1.0, true, true);
        }
    }

    /**
     * Result of analyzing a single response.
     */
    public record AnalysisResult(
            Map<String, List<String>> matchesPerModel,
            Map<String, Double> confidencePerModel
    ) {
        public AnalysisResult {
            matchesPerModel = matchesPerModel != null ? Map.copyOf(matchesPerModel) : Map.of();
            confidencePerModel = confidencePerModel != null ? Map.copyOf(confidencePerModel) : Map.of();
        }

        public static AnalysisResult empty() {
            return new AnalysisResult(Map.of(), Map.of());
        }

    }

    /**
     * Response length statistics.
     */
    public record ResponseLengthAnalysis(
            int characters,
            int words,
            int lines,
            int sentences,
            double avgWordsPerSentence
    ) {
        public String category() {
            if (words < 50) return "concise";
            if (words < 150) return "moderate";
            if (words < 300) return "detailed";
            return "verbose";
        }
    }

    public FingerprintAnalyzer() {
        this(ModelFingerprint.all(), AnalysisConfig.defaults());
    }

    public FingerprintAnalyzer(final List<ModelFingerprint> candidates, final AnalysisConfig config) {
        this.candidateModels = List.copyOf(candidates);
        this.config = config;
    }

    public AnalysisResult analyze(final FingerprintProbe probe, final String response) {
        if (response == null || response.isBlank()) {
            return AnalysisResult.empty();
        }

        final String normalizedResponse = config.caseInsensitive() ?
                response.toLowerCase() : response;

        final Map<String, List<String>> matchesPerModel = new HashMap<>();
        final Map<String, Double> confidencePerModel = new HashMap<>();

        analyzeExpectedPatterns(probe, normalizedResponse, matchesPerModel, confidencePerModel);
        analyzeSelfIdPatterns(probe, normalizedResponse, matchesPerModel, confidencePerModel);
        analyzeStylePatterns(probe, response, confidencePerModel);
        analyzeRefusalPatterns(probe, normalizedResponse, matchesPerModel, confidencePerModel);

        return new AnalysisResult(matchesPerModel, confidencePerModel);
    }

    private void analyzeExpectedPatterns(
            final FingerprintProbe probe,
            final String normalizedResponse,
            final Map<String, List<String>> matchesPerModel,
            final Map<String, Double> confidencePerModel
    ) {
        for (final Map.Entry<String, List<String>> entry : probe.expectedPatterns().entrySet()) {
            final String modelId = entry.getKey();
            final List<String> patterns = entry.getValue();
            final List<String> foundMatches = new ArrayList<>();
            double patternScore = 0.0;

            for (final String pattern : patterns) {
                final String searchPattern = config.caseInsensitive() ?
                        pattern.toLowerCase() : pattern;

                if (normalizedResponse.contains(searchPattern)) {
                    foundMatches.add(pattern);
                    patternScore += probe.weight();
                }
            }

            if (!foundMatches.isEmpty()) {
                matchesPerModel.put(modelId, foundMatches);
                final double matchRatio = (double) foundMatches.size() / patterns.size();
                confidencePerModel.put(modelId, patternScore * matchRatio);
            }
        }
    }

    private void analyzeSelfIdPatterns(
            final FingerprintProbe probe,
            final String normalizedResponse,
            final Map<String, List<String>> matchesPerModel,
            final Map<String, Double> confidencePerModel
    ) {
        for (final ModelFingerprint model : candidateModels) {
            final double selfIdScore = analyzeSelfIdentification(model, normalizedResponse);
            if (selfIdScore > 0 && probe.category() == FingerprintProbe.FingerprintCategory.SELF_IDENTIFICATION) {
                confidencePerModel.merge(model.id(), selfIdScore * probe.weight(), Double::sum);

                final List<String> selfIdMatches = findSelfIdMatches(model, normalizedResponse);
                if (!selfIdMatches.isEmpty()) {
                    matchesPerModel.computeIfAbsent(model.id(), k -> new ArrayList<>())
                            .addAll(selfIdMatches);
                }
            }
        }
    }

    private void analyzeStylePatterns(
            final FingerprintProbe probe,
            final String response,
            final Map<String, Double> confidencePerModel
    ) {
        if (config.analyzeStyle() && probe.category() == FingerprintProbe.FingerprintCategory.STYLE) {
            final Map<String, Double> styleScores = analyzeResponseStyle(response);
            for (final Map.Entry<String, Double> entry : styleScores.entrySet()) {
                confidencePerModel.merge(entry.getKey(),
                        entry.getValue() * probe.weight() * 0.5, Double::sum);
            }
        }
    }

    private void analyzeRefusalPatterns(
            final FingerprintProbe probe,
            final String normalizedResponse,
            final Map<String, List<String>> matchesPerModel,
            final Map<String, Double> confidencePerModel
    ) {
        if (probe.category() != FingerprintProbe.FingerprintCategory.REFUSAL_STYLE) {
            return;
        }

        final Map<String, Double> refusalScores = analyzeRefusalStyle(normalizedResponse);
        for (final Map.Entry<String, Double> entry : refusalScores.entrySet()) {
            confidencePerModel.merge(entry.getKey(),
                    entry.getValue() * probe.weight(), Double::sum);

            final List<String> refusalMatches = findRefusalMatches(entry.getKey(), normalizedResponse);
            if (!refusalMatches.isEmpty()) {
                matchesPerModel.computeIfAbsent(entry.getKey(), k -> new ArrayList<>())
                        .addAll(refusalMatches);
            }
        }
    }

    private double analyzeSelfIdentification(final ModelFingerprint model, final String response) {
        double score = 0.0;
        int matchCount = 0;

        for (final String pattern : model.selfIdentificationPatterns()) {
            final String searchPattern = config.caseInsensitive() ?
                    pattern.toLowerCase() : pattern;

            if (response.contains(searchPattern)) {
                matchCount++;
                score += (pattern.length() > 10) ?
                        config.exactMatchMultiplier() : config.partialMatchMultiplier();
            }
        }

        if (!model.selfIdentificationPatterns().isEmpty()) {
            score = score * matchCount / model.selfIdentificationPatterns().size();
        }

        return score;
    }

    private List<String> findSelfIdMatches(final ModelFingerprint model, final String response) {
        final List<String> matches = new ArrayList<>();
        for (final String pattern : model.selfIdentificationPatterns()) {
            final String searchPattern = config.caseInsensitive() ?
                    pattern.toLowerCase() : pattern;
            if (response.contains(searchPattern)) {
                matches.add(pattern);
            }
        }
        return matches;
    }

    private Map<String, Double> analyzeResponseStyle(final String response) {
        final Map<String, Double> scores = new HashMap<>();

        final boolean usesMarkdown = response.contains("**") || response.contains("##") ||
                response.contains("```");
        final boolean usesBulletPoints = response.contains("- ") || response.contains("• ") ||
                Pattern.compile("^\\d+\\.", Pattern.MULTILINE).matcher(response).find();
        final boolean usesCodeBlocks = response.contains("```");

        for (final ModelFingerprint model : candidateModels) {
            final double styleScore = calculateStyleScore(model, response, usesMarkdown,
                    usesBulletPoints, usesCodeBlocks);
            if (styleScore > 0) {
                scores.put(model.id(), styleScore);
            }
        }

        return scores;
    }

    private double calculateStyleScore(
            final ModelFingerprint model,
            final String response,
            final boolean usesMarkdown,
            final boolean usesBulletPoints,
            final boolean usesCodeBlocks
    ) {
        double styleScore = 0.0;
        final ModelFingerprint.ResponseStyle style = model.responseStyle();

        if (style.usesMarkdown() == usesMarkdown) styleScore += 0.2;
        if (style.usesBulletPoints() == usesBulletPoints) styleScore += 0.2;
        if (style.usesCodeBlocks() == usesCodeBlocks) styleScore += 0.2;

        final String lowerResponse = response.toLowerCase();
        for (final String phrase : style.commonPhrases()) {
            if (lowerResponse.contains(phrase.toLowerCase())) {
                styleScore += 0.15;
            }
        }
        for (final String phrase : style.avoidedPhrases()) {
            if (lowerResponse.contains(phrase.toLowerCase())) {
                styleScore -= 0.1;
            }
        }

        return styleScore;
    }

    private Map<String, Double> analyzeRefusalStyle(final String response) {
        final Map<String, Double> scores = new HashMap<>();

        for (final ModelFingerprint model : candidateModels) {
            int matchCount = 0;
            for (final String pattern : model.refusalPatterns()) {
                final String searchPattern = config.caseInsensitive() ?
                        pattern.toLowerCase() : pattern;
                if (response.contains(searchPattern)) {
                    matchCount++;
                }
            }

            if (matchCount > 0) {
                final double ratio = (double) matchCount / model.refusalPatterns().size();
                scores.put(model.id(), ratio * 0.8);
            }
        }

        return scores;
    }

    private List<String> findRefusalMatches(final String modelId, final String response) {
        final List<String> matches = new ArrayList<>();
        final ModelFingerprint model = ModelFingerprint.byId(modelId);
        if (model == null) return matches;

        for (final String pattern : model.refusalPatterns()) {
            final String searchPattern = config.caseInsensitive() ?
                    pattern.toLowerCase() : pattern;
            if (response.contains(searchPattern)) {
                matches.add("Refusal: " + pattern);
            }
        }
        return matches;
    }

    public ResponseLengthAnalysis analyzeLength(final String response) {
        final int charCount = response.length();
        final int wordCount = response.split("\\s+").length;
        final int lineCount = response.split("\n").length;
        final int sentenceCount = response.split("[.!?]+").length;
        final double avgWordsPerSentence = sentenceCount > 0 ?
                (double) wordCount / sentenceCount : wordCount;

        return new ResponseLengthAnalysis(
                charCount, wordCount, lineCount, sentenceCount, avgWordsPerSentence);
    }

    public Map<String, Double> analyzeBehavioralSignatures(
            final Map<FingerprintProbe, String> probeResponses
    ) {
        final Map<String, Double> scores = new HashMap<>();

        for (final ModelFingerprint model : candidateModels) {
            final double signatureScore = calculateBehavioralScore(model, probeResponses);
            if (signatureScore > 0) {
                scores.put(model.id(), signatureScore);
            }
        }

        return scores;
    }

    private double calculateBehavioralScore(
            final ModelFingerprint model,
            final Map<FingerprintProbe, String> probeResponses
    ) {
        double signatureScore = 0.0;

        for (final ModelFingerprint.BehavioralSignature signature : model.behavioralSignatures()) {
            for (final Map.Entry<FingerprintProbe, String> entry : probeResponses.entrySet()) {
                final String promptPrefix = signature.testPrompt().substring(0,
                        Math.min(20, signature.testPrompt().length()));

                if (entry.getKey().prompt().contains(promptPrefix)) {
                    final String response = entry.getValue().toLowerCase();
                    int patternMatches = 0;

                    for (final String pattern : signature.expectedPatterns()) {
                        if (response.contains(pattern.toLowerCase())) {
                            patternMatches++;
                        }
                    }

                    if (patternMatches > 0) {
                        final double matchRatio = (double) patternMatches / signature.expectedPatterns().size();
                        signatureScore += matchRatio * signature.weight();
                    }
                }
            }
        }

        return signatureScore;
    }

    public Optional<String> extractVersionHint(final String response) {
        final List<Pattern> versionPatterns = List.of(
                Pattern.compile("(?:GPT|gpt)[- ]?(\\d+(?:\\.\\d+)?(?:[- ]?[a-zA-Z]+)?)", Pattern.CASE_INSENSITIVE),
                Pattern.compile("(?:Claude|claude)[- ]?(\\d+(?:\\.\\d+)?(?:[- ]?[a-zA-Z]+)?)", Pattern.CASE_INSENSITIVE),
                Pattern.compile("(?:Llama|llama)[- ]?(\\d+(?:\\.\\d+)?)", Pattern.CASE_INSENSITIVE),
                Pattern.compile("(?:Gemini|gemini)[- ]?(\\d+(?:\\.\\d+)?(?:[- ]?[a-zA-Z]+)?)", Pattern.CASE_INSENSITIVE),
                Pattern.compile("(?:Mistral|mistral)[- ]?(\\d+(?:\\.\\d+)?(?:[- ]?[a-zA-Z]+)?)", Pattern.CASE_INSENSITIVE)
        );

        for (final Pattern pattern : versionPatterns) {
            final Matcher matcher = pattern.matcher(response);
            if (matcher.find()) {
                return Optional.of(matcher.group(0));
            }
        }

        return Optional.empty();
    }

}
