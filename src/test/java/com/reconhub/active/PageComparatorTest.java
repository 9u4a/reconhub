package com.reconhub.active;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code similarity(Set, String)} (0.43.9) -- added so {@code BruteforceEngine} can compute the fixed
 * baseline body's shingles once per job instead of on every probe. Verifies the new overload agrees
 * exactly with the original {@code similarity(String, String)} it's built from.
 */
class PageComparatorTest {

    @Test
    void shinglesOfPlusNewOverloadAgreesWithOriginalSimilarity() {
        String base = "<html><body>Not Found: /admin/dashboard-493201 at 2024-01-01</body></html>";
        String other = "<html><body>Not Found: /__reconhub_582910__ at 2024-06-15</body></html>";

        double viaOriginal = PageComparator.similarity(base, other);
        double viaNewOverload = PageComparator.similarity(PageComparator.shinglesOf(base), other);

        assertEquals(viaOriginal, viaNewOverload, 0.0);
    }

    @Test
    void shinglesOfAgreesWithOriginalOnIdenticalBodies() {
        String body = "the quick brown fox jumps over the lazy dog";
        assertEquals(1.0, PageComparator.similarity(PageComparator.shinglesOf(body), body));
    }

    @Test
    void shinglesOfOnEmptyBodyIsEmptySet() {
        assertTrue(PageComparator.shinglesOf("").isEmpty());
        assertTrue(PageComparator.shinglesOf(null).isEmpty());
    }

    @Test
    void newOverloadMatchesOriginalAcrossEmptyAndNonEmptyCombinations() {
        Set<String> emptyShingles = PageComparator.shinglesOf("");
        assertEquals(PageComparator.similarity("", ""),
                PageComparator.similarity(emptyShingles, ""));
        assertEquals(PageComparator.similarity("", "something"),
                PageComparator.similarity(emptyShingles, "something"));

        Set<String> nonEmptyShingles = PageComparator.shinglesOf("something here");
        assertEquals(PageComparator.similarity("something here", ""),
                PageComparator.similarity(nonEmptyShingles, ""));
    }
}
