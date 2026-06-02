package io.tiberius.core.buff;

/**
 * A Buff is a transformation/mutation applied to a probe's prompt.
 * Buffs are used to test evasion techniques such as encoding,
 * paraphrasing, or stylistic transformations.
 */
@FunctionalInterface
public interface Buff {

    /**
     * Transform the input prompt.
     *
     * @param input the original prompt
     * @return the transformed prompt
     */
    String transform(final String input);

    /**
     * Get the name of this buff.
     */
    default String getName() {
        return getClass().getSimpleName();
    }

    /**
     * Get a description of this buff.
     */
    default String getDescription() {
        return "Transforms the prompt using " + getName();
    }

    /**
     * Chain this buff with another buff.
     *
     * @param after the buff to apply after this one
     * @return a new buff that applies both transformations
     */
    default Buff andThen(final Buff after) {
        return input -> after.transform(this.transform(input));
    }

    /**
     * Create a buff that applies before this one.
     *
     * @param before the buff to apply before this one
     * @return a new buff that applies both transformations
     */
    default Buff compose(final Buff before) {
        return input -> this.transform(before.transform(input));
    }

    /**
     * Identity buff that returns the input unchanged.
     */
    static Buff identity() {
        return input -> input;
    }
}
