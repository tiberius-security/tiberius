package io.tiberius.punit;

import org.javai.punit.api.criterion.Criteria;
import org.javai.punit.api.criterion.CriterionDecl;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for SecurityCriteria helper class.
 */
class SecurityCriteriaTest {

    @Test
    @DisplayName("standard() creates valid criterion declaration")
    void standardCreatesValidCriterion() {
        CriterionDecl<AttackOutcome> criterion = SecurityCriteria.standard();
        assertNotNull(criterion);
        assertTrue(criterion.name().isPresent());
        assertEquals("standard-security", criterion.name().get());
    }

    @Test
    @DisplayName("strict() creates valid criterion declaration")
    void strictCreatesValidCriterion() {
        CriterionDecl<AttackOutcome> criterion = SecurityCriteria.strict();
        assertNotNull(criterion);
        assertTrue(criterion.name().isPresent());
        assertEquals("strict-security", criterion.name().get());
    }

    @Test
    @DisplayName("zeroTolerance() creates valid criterion declaration")
    void zeroToleranceCreatesValidCriterion() {
        CriterionDecl<AttackOutcome> criterion = SecurityCriteria.zeroTolerance();
        assertNotNull(criterion);
        assertTrue(criterion.name().isPresent());
        assertEquals("zero-tolerance", criterion.name().get());
    }

    @Test
    @DisplayName("lenient() creates valid criterion declaration")
    void lenientCreatesValidCriterion() {
        CriterionDecl<AttackOutcome> criterion = SecurityCriteria.lenient();
        assertNotNull(criterion);
        assertTrue(criterion.name().isPresent());
        assertEquals("lenient-security", criterion.name().get());
    }

    @Test
    @DisplayName("promptInjectionResistant() creates OWASP LLM01 criterion")
    void promptInjectionResistantCreatesOwaspCriterion() {
        CriterionDecl<AttackOutcome> criterion = SecurityCriteria.promptInjectionResistant();
        assertNotNull(criterion);
        assertTrue(criterion.name().isPresent());
        assertEquals("owasp-llm01-prompt-injection", criterion.name().get());
    }

    @Test
    @DisplayName("noDataLeakage() creates OWASP LLM06 criterion")
    void noDataLeakageCreatesOwaspCriterion() {
        CriterionDecl<AttackOutcome> criterion = SecurityCriteria.noDataLeakage();
        assertNotNull(criterion);
        assertTrue(criterion.name().isPresent());
        assertEquals("owasp-llm06-data-protection", criterion.name().get());
    }

    @Test
    @DisplayName("highSeverityOnly() creates valid criterion")
    void highSeverityOnlyCreatesValidCriterion() {
        CriterionDecl<AttackOutcome> criterion = SecurityCriteria.highSeverityOnly();
        assertNotNull(criterion);
        assertTrue(criterion.name().isPresent());
        assertEquals("high-severity-protection", criterion.name().get());
    }

    @Test
    @DisplayName("executionReliability() creates valid criterion")
    void executionReliabilityCreatesValidCriterion() {
        CriterionDecl<AttackOutcome> criterion = SecurityCriteria.executionReliability();
        assertNotNull(criterion);
        assertTrue(criterion.name().isPresent());
        assertEquals("execution-reliability", criterion.name().get());
    }

    @Test
    @DisplayName("owaspCompliant() creates composite criteria")
    void owaspCompliantCreatesCompositeCriteria() {
        Criteria<AttackOutcome> criteria = SecurityCriteria.owaspCompliant();
        assertNotNull(criteria);
        assertFalse(criteria.isEmpty());
        // Should have at least standard and execution reliability
        assertTrue(criteria.asList().size() >= 2);
    }

    @Test
    @DisplayName("productionReady() creates composite criteria")
    void productionReadyCreatesCompositeCriteria() {
        Criteria<AttackOutcome> criteria = SecurityCriteria.productionReady();
        assertNotNull(criteria);
        assertFalse(criteria.isEmpty());
        // Should have strict, high severity, and execution reliability
        assertTrue(criteria.asList().size() >= 3);
    }

    @Test
    @DisplayName("Criteria can be converted to list")
    void criteriaCanBeConvertedToList() {
        Criteria<AttackOutcome> criteria = SecurityCriteria.owaspCompliant();
        var list = criteria.asList();
        assertNotNull(list);
        assertFalse(list.isEmpty());
    }
}
