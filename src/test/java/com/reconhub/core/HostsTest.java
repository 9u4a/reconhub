package com.reconhub.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** {@code Hosts.of}/{@code label} -- the 0.41.0 consolidation of 7 near-identical private copies that
 * had accumulated across core/ui/export/analysis. Pure logic, headless. */
class HostsTest {

    // ---- of() ------------------------------------------------------------------------------------

    @Test
    void extractsHostFromAnAbsoluteHttpUrl() {
        assertEquals("example.com", Hosts.of("http://example.com/a/b?x=1"));
    }

    @Test
    void extractsHostFromAnAbsoluteHttpsUrlWithPort() {
        assertEquals("example.com", Hosts.of("https://example.com:8443/a"));
    }

    @Test
    void preservesHostCaseExactlyAsGiven() {
        // Hosts.of doesn't lowercase -- callers that need case-insensitive comparison do that themselves
        // (e.g. RunBruteforceAction.schemesByHost).
        assertEquals("Example.COM", Hosts.of("http://Example.COM/a"));
    }

    @Test
    void nonHttpAbsoluteUrlWithAuthorityStillYieldsItsHost() {
        // The one case where FindingsPanel's old hostOf differed (it rejected anything not starting
        // with "http") -- ftp/ws schemes with an authority component still parse fine via URI.
        assertEquals("h.example", Hosts.of("ftp://h.example/file"));
    }

    @Test
    void nullIsEmptyString() {
        assertEquals("", Hosts.of(null));
    }

    @Test
    void blankIsEmptyString() {
        assertEquals("", Hosts.of("   "));
    }

    @Test
    void relativePathIsEmptyString() {
        assertEquals("", Hosts.of("/a/b/c"));
    }

    @Test
    void unparseableUrlIsEmptyStringNotAnException() {
        assertEquals("", Hosts.of("http://[not-a-valid-host"));
    }

    @Test
    void schemeRelativeUrlWithNoHostIsEmptyString() {
        assertEquals("", Hosts.of("mailto:someone@example.com"));
    }

    // ---- label() -----------------------------------------------------------------------------------

    @Test
    void labelPassesThroughANonEmptyHost() {
        assertEquals("example.com", Hosts.label("example.com"));
    }

    @Test
    void labelOfNullIsThePlaceholder() {
        assertEquals("(relative / JS)", Hosts.label(null));
    }

    @Test
    void labelOfBlankIsThePlaceholder() {
        assertEquals("(relative / JS)", Hosts.label(""));
    }

    // ---- labelOf() (of + label composed) ------------------------------------------------------------

    @Test
    void labelOfComposesExtractionAndLabeling() {
        assertEquals("example.com", Hosts.labelOf("http://example.com/a"));
        assertEquals("(relative / JS)", Hosts.labelOf("/a/b"));
        assertEquals("(relative / JS)", Hosts.labelOf(null));
    }
}
