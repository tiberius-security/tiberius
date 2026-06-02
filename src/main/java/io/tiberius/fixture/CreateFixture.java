package io.tiberius.fixture;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to mark a test method for fixture-based validation.
 *
 * <p>Supports two modes:
 * <ul>
 *   <li><b>Normal mode</b> (default): Compares individual scan results</li>
 *   <li><b>Statistical mode</b>: Aggregates results per probe and compares block rates within tolerance</li>
 * </ul>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface CreateFixture {

    /** Fixture file path relative to test resources */
    String value();

    /** Fixture version */
    String version() default "1.0.0";

    /** Create fixture file if it doesn't exist */
    boolean createIfMissing() default true;

    /** Update fixture file when results differ */
    boolean updateOnChange() default false;

    /** Fixture description */
    String description() default "";

    /**
     * Enable statistical mode for multi-trial scans.
     * When enabled, results are aggregated per probe and compared by block rate.
     */
    boolean statisticalMode() default false;

    /**
     * Tolerance for statistical comparison (0.0 to 1.0).
     * Only used when statisticalMode is true.
     * Default is 0.1 (10% tolerance).
     */
    double tolerance() default 0.1;
}
