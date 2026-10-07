package com.reconhub.analysis;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code classifyCached} (0.43.7) -- the memoized variant hot paths (Dashboard, RequestInspector,
 * exporters) should prefer over the uncached {@code classify}. Only verifies the cache is behavior-
 * preserving (same answer, repeatedly) -- the classification rules themselves are covered by
 * {@code classify}'s own long-standing behavior, unchanged here.
 */
class ParameterClassifierTest {

    @Test
    void classifyCachedMatchesUncachedClassify() {
        // A name that's expected to hit at least one real rule (redirect-like), so this isn't just
        // asserting two empty lists are equal.
        assertEquals(ParameterClassifier.classify("redirect_url"),
                ParameterClassifier.classifyCached("redirect_url"));
    }

    @Test
    void classifyCachedIsStableAcrossRepeatedCalls() {
        List<String> first = ParameterClassifier.classifyCached("token");
        List<String> second = ParameterClassifier.classifyCached("token");
        assertEquals(first, second);
    }

    @Test
    void classifyCachedOnBlankOrNullNameIsEmpty() {
        assertTrue(ParameterClassifier.classifyCached(null).isEmpty());
        assertTrue(ParameterClassifier.classifyCached("").isEmpty());
        assertTrue(ParameterClassifier.classifyCached("   ").isEmpty());
    }

    @Test
    void classifyCachedOnAnUnclassifiedNameIsEmpty() {
        // No underscores and not equal to any whole rule keyword, so none of param-classes.json's
        // "(^|_)keyword($|_)"-shaped rules can match anywhere in it.
        assertTrue(ParameterClassifier.classifyCached("zzqqxxyy").isEmpty());
    }
}
