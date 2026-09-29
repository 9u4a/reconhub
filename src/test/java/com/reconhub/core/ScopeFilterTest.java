package com.reconhub.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code ScopeFilter.inScope} -- base scope (Burp scope / all traffic) further narrowed by optional
 * include/exclude regexes. Written to directly verify the user's "does include/exclude actually work?"
 * question, since there was no prior committed test for this class. Pure logic against a real {@link
 * Settings} + {@link ApiStub} (its {@code scope().isInScope} stub always returns true unless told to
 * throw, so {@code Settings.ScopeMode.ALL} and the default {@code BURP_SCOPE} behave identically here
 * except where a test explicitly exercises the throw path). */
class ScopeFilterTest {

    // ---- base scope only (no include/exclude set) ----------------------------------------------------

    @Test
    void withNoRegexesEverythingPassesUnderAllMode() {
        Settings s = new Settings();
        s.setScopeMode(Settings.ScopeMode.ALL);
        ScopeFilter f = new ScopeFilter(new ApiStub().api, s);
        assertTrue(f.inScope("http://anything.example/a"));
    }

    @Test
    void withNoRegexesBurpScopeAloneDecides() {
        ApiStub stub = new ApiStub();   // isInScope always true by default
        Settings s = new Settings();
        s.setScopeMode(Settings.ScopeMode.BURP_SCOPE);
        ScopeFilter f = new ScopeFilter(stub.api, s);
        assertTrue(f.inScope("http://anything.example/a"));
    }

    @Test
    void burpScopeCheckExceptionMeansOutOfScopeNotACrash() {
        ApiStub stub = new ApiStub();
        stub.makeScopeCheckThrow();
        Settings s = new Settings();
        s.setScopeMode(Settings.ScopeMode.BURP_SCOPE);
        ScopeFilter f = new ScopeFilter(stub.api, s);
        assertFalse(f.inScope("http://h.example/a"));
        assertFalse(stub.errorLog.isEmpty());   // logged, not silent (0.35.0 regression guard)
    }

    @Test
    void allModeNeverConsultsBurpScopeEvenIfItWouldThrow() {
        ApiStub stub = new ApiStub();
        stub.makeScopeCheckThrow();
        Settings s = new Settings();
        s.setScopeMode(Settings.ScopeMode.ALL);
        ScopeFilter f = new ScopeFilter(stub.api, s);
        assertTrue(f.inScope("http://h.example/a"));
        assertTrue(stub.errorLog.isEmpty());
    }

    // ---- include regex ---------------------------------------------------------------------------

    @Test
    void includeRegexNarrowsToMatchingUrlsOnly() {
        Settings s = allMode();
        s.setScopeIncludeRegex("api\\.example");
        ScopeFilter f = new ScopeFilter(new ApiStub().api, s);

        assertTrue(f.inScope("https://api.example/v1/users"));
        assertFalse(f.inScope("https://other.example/v1/users"));
    }

    @Test
    void emptyIncludeRegexMeansNotSet() {
        Settings s = allMode();
        s.setScopeIncludeRegex("");
        ScopeFilter f = new ScopeFilter(new ApiStub().api, s);
        assertTrue(f.inScope("https://anything.example/a"));
    }

    @Test
    void includeRegexUsesFindNotWholeStringMatch() {
        // Pattern.matcher(url).find() -- a partial match anywhere in the URL is enough, matching what a
        // user typing a bare hostname fragment into the field would expect.
        Settings s = allMode();
        s.setScopeIncludeRegex("admin");
        ScopeFilter f = new ScopeFilter(new ApiStub().api, s);
        assertTrue(f.inScope("https://h.example/app/admin/users"));
    }

    // ---- exclude regex ---------------------------------------------------------------------------

    @Test
    void excludeRegexDropsMatchingUrlsEvenWithNoIncludeSet() {
        Settings s = allMode();
        s.setScopeExcludeRegex("\\.(png|jpg|css)$");
        ScopeFilter f = new ScopeFilter(new ApiStub().api, s);

        assertTrue(f.inScope("https://h.example/a.js"));
        assertFalse(f.inScope("https://h.example/a.png"));
    }

    @Test
    void emptyExcludeRegexMeansNotSet() {
        Settings s = allMode();
        s.setScopeExcludeRegex("");
        ScopeFilter f = new ScopeFilter(new ApiStub().api, s);
        assertTrue(f.inScope("https://anything.example/a.png"));
    }

    // ---- include + exclude combined ---------------------------------------------------------------

    @Test
    void mustMatchIncludeAndNotMatchExclude() {
        Settings s = allMode();
        s.setScopeIncludeRegex("api\\.example");
        s.setScopeExcludeRegex("/internal/");
        ScopeFilter f = new ScopeFilter(new ApiStub().api, s);

        assertTrue(f.inScope("https://api.example/v1/users"));
        assertFalse(f.inScope("https://api.example/v1/internal/users"));  // matches include, but excluded
        assertFalse(f.inScope("https://other.example/v1/users"));         // doesn't match include at all
    }

    @Test
    void excludeWinsOverIncludeWhenBothMatch() {
        Settings s = allMode();
        s.setScopeIncludeRegex("h\\.example");
        s.setScopeExcludeRegex("h\\.example");   // deliberately identical -- exclude must still win
        ScopeFilter f = new ScopeFilter(new ApiStub().api, s);
        assertFalse(f.inScope("https://h.example/a"));
    }

    // ---- invalid regex: fails OPEN (documented trade-off, not a bug) ------------------------------

    @Test
    void invalidIncludeRegexIsTreatedAsNotSetRatherThanCrashing() {
        // ScopeFilter.compile() itself is defense-in-depth: SettingsPanel.validateRegex is what
        // actually stops an invalid regex from being saved in the normal UI flow, but ScopeFilter must
        // not crash ingestion even if an invalid string reaches it some other way (e.g. a hand-edited
        // preferences file). Documented trade-off: this WIDENS scope back to unfiltered rather than
        // narrowing to nothing -- see the CLAUDE.md 0.35.0 note this test locks in.
        Settings s = allMode();
        s.setScopeIncludeRegex("[unterminated");
        ScopeFilter f = new ScopeFilter(new ApiStub().api, s);
        assertTrue(f.inScope("https://anything.example/a"));
    }

    @Test
    void invalidExcludeRegexIsTreatedAsNotSet() {
        Settings s = allMode();
        s.setScopeExcludeRegex("[unterminated");
        ScopeFilter f = new ScopeFilter(new ApiStub().api, s);
        assertTrue(f.inScope("https://anything.example/a"));
    }

    // ---- live update: changing Settings after construction is picked up ---------------------------

    @Test
    void changingTheIncludeRegexAfterConstructionIsPickedUpOnNextCall() {
        // ScopeFilter caches its compiled Pattern, recompiling only when the source string changes
        // (includeSrc/includePat) -- must not go stale across a SettingsPanel "Apply" click, since one
        // ScopeFilter instance lives for the life of TrafficIngestor, not recreated per apply.
        Settings s = allMode();
        ScopeFilter f = new ScopeFilter(new ApiStub().api, s);
        assertTrue(f.inScope("https://other.example/a"));

        s.setScopeIncludeRegex("api\\.example");
        assertFalse(f.inScope("https://other.example/a"));
        assertTrue(f.inScope("https://api.example/a"));
    }

    private static Settings allMode() {
        Settings s = new Settings();
        s.setScopeMode(Settings.ScopeMode.ALL);   // isolates include/exclude from Burp-scope stubbing
        return s;
    }
}
