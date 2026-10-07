package com.reconhub.analysis;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * {@code categoryOf} (0.43.7 added an internal cache keyed by {@code type}) -- verifies the cache is
 * behavior-preserving: repeated calls for the same type return an equal (and, since {@code Category}
 * is an enum, the same singleton) result, and the existing keyword-based classification is unaffected.
 */
class FindingTaxonomyTest {

    @Test
    void categoryOfIsStableAndCachedAcrossRepeatedCalls() {
        FindingTaxonomy.Category first = FindingTaxonomy.categoryOf("Secret in URL");
        FindingTaxonomy.Category second = FindingTaxonomy.categoryOf("Secret in URL");
        assertSame(first, second);
        assertEquals(FindingTaxonomy.Category.SECRET, first);
    }

    @Test
    void categoryOfStillClassifiesByKeyword() {
        assertEquals(FindingTaxonomy.Category.MISCONFIG, FindingTaxonomy.categoryOf("CORS wildcard"));
        assertEquals(FindingTaxonomy.Category.PII, FindingTaxonomy.categoryOf("Korean RRN (주민등록번호)"));
        assertEquals(FindingTaxonomy.Category.COMMENT, FindingTaxonomy.categoryOf("JS Comment"));
    }

    @Test
    void categoryOfOnBlankOrNullTypeIsOther() {
        assertEquals(FindingTaxonomy.Category.OTHER, FindingTaxonomy.categoryOf(null));
        assertEquals(FindingTaxonomy.Category.OTHER, FindingTaxonomy.categoryOf(""));
        assertEquals(FindingTaxonomy.Category.OTHER, FindingTaxonomy.categoryOf("   "));
    }

    @Test
    void categoryOfOnAnUnclassifiedTypeIsOther() {
        assertEquals(FindingTaxonomy.Category.OTHER, FindingTaxonomy.categoryOf("Zzqqxxyy Widget"));
    }
}
