package com.reconhub.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code SearchQuery} -- extracted from {@code AbstractTablePanel.applySearch}/{@code SearchFilter}
 * (0.43.0) so {@code GlobalSearchDialog} can reuse the exact same matching semantics. Pure logic,
 * headless; a behavior-preserving extraction, so these cases also lock in every per-tab search's
 * existing behavior. */
class SearchQueryTest {

    @Test
    void emptyQueryMatchesEverything() {
        SearchQuery q = SearchQuery.parse("", false, false);
        assertTrue(q.isEmpty());
        assertTrue(q.matches("anything"));
        assertTrue(q.matches(""));
    }

    @Test
    void blankQueryIsTreatedAsEmpty() {
        SearchQuery q = SearchQuery.parse("   ", false, false);
        assertTrue(q.isEmpty());
    }

    @Test
    void singleTermMatchesSubstring() {
        SearchQuery q = SearchQuery.parse("admin", false, false);
        assertFalse(q.isEmpty());
        assertTrue(q.matches("GET /api/admin/users"));
        assertFalse(q.matches("GET /api/users"));
    }

    @Test
    void multipleTermsAreAnded() {
        SearchQuery q = SearchQuery.parse("admin users", false, false);
        assertTrue(q.matches("GET /api/admin/users"));
        assertFalse(q.matches("GET /api/admin/roles"));
        assertFalse(q.matches("GET /api/users"));
    }

    @Test
    void dashPrefixExcludesMatchingRows() {
        SearchQuery q = SearchQuery.parse("api -admin", false, false);
        assertTrue(q.matches("GET /api/users"));
        assertFalse(q.matches("GET /api/admin/users"));
    }

    @Test
    void aLoneDashIsTreatedAsALiteralIncludeTermNotAnEmptyExclude() {
        // tok.length() > 1 guards the exclude check, so a solitary "-" token (length 1) takes the
        // non-exclude branch and becomes a literal include term matching the dash character itself --
        // it is NOT silently dropped as "exclude of nothing".
        SearchQuery q = SearchQuery.parse("-", false, false);
        assertFalse(q.isEmpty());
        assertTrue(q.matches("a-b"));
        assertFalse(q.matches("ab"));
    }

    @Test
    void caseInsensitiveByDefault() {
        SearchQuery q = SearchQuery.parse("ADMIN", false, false);
        assertTrue(q.matches("get /admin/users"));
    }

    @Test
    void caseSensitiveWhenRequested() {
        SearchQuery q = SearchQuery.parse("ADMIN", false, true);
        assertFalse(q.matches("get /admin/users"));
        assertTrue(q.matches("get /ADMIN/users"));
    }

    @Test
    void literalModeTreatsRegexMetacharactersAsLiteral() {
        SearchQuery q = SearchQuery.parse("a.b", false, false);
        assertTrue(q.matches("x a.b y"));
        assertFalse(q.matches("x aXb y"));   // would match if '.' were treated as regex wildcard
    }

    @Test
    void regexModeCompilesTermsAsPatterns() {
        SearchQuery q = SearchQuery.parse("admin|root", true, false);
        assertTrue(q.matches("logged in as root"));
        assertTrue(q.matches("logged in as admin"));
        assertFalse(q.matches("logged in as guest"));
    }

    @Test
    void invalidRegexFallsBackToLiteralInsteadOfThrowing() {
        SearchQuery q = SearchQuery.parse("[unterminated", true, false);
        assertTrue(q.matches("has [unterminated bracket"));
        assertFalse(q.matches("no match here"));
    }

    @Test
    void excludeAloneWithNoIncludesStillFilters() {
        SearchQuery q = SearchQuery.parse("-admin", false, false);
        assertFalse(q.isEmpty());
        assertTrue(q.matches("users"));
        assertFalse(q.matches("admin"));
    }
}
