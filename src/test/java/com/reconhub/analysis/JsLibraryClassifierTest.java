package com.reconhub.analysis;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code JsLibraryClassifier} (0.55.0) against the shipped js-libraries.json. Pure logic, headless. */
class JsLibraryClassifierTest {

    private static final JsLibraryClassifier C = JsLibraryClassifier.shared();

    @Test
    void rulesLoadWithoutErrors() {
        assertTrue(C.loadErrors().isEmpty(), C.loadErrors().toString());
        assertTrue(C.rules().size() > 10);
    }

    @Test
    void thirdPartyHostsAreTagged() {
        assertEquals("3rd-party: Google Tag Manager / Analytics / Ads",
                C.classify("https://www.googletagmanager.com/gtm.js?id=GTM-X", "x"));
        assertEquals("3rd-party: Public CDN library",
                C.classify("https://cdn.jsdelivr.net/npm/foo@1/dist/foo.js", "x"));
        assertTrue(C.classify("https://cdn.channel.io/plugin/ch-plugin-web.js", "x").startsWith("3rd-party"));
    }

    @Test
    void libraryFileNamesAreTagged() {
        assertEquals("Library: jQuery", C.classify("https://app.example/static/jquery-3.6.0.min.js", "x"));
        assertEquals("Library: React", C.classify("https://app.example/js/react-dom.production.min.js", "x"));
        assertEquals("Library: Polyfill", C.classify("https://app.example/js/polyfills.js?v=3", "x"));
    }

    @Test
    void vendorAndRuntimeChunksAreTagged() {
        assertEquals("Vendor chunk", C.classify("https://app.example/static/js/vendors~main.1a2b3c.chunk.js", "x"));
        assertEquals("Vendor chunk", C.classify("https://app.example/js/chunk-vendors.9f8e.js", "x"));
        assertEquals("Framework / runtime chunk",
                C.classify("https://app.example/_next/static/chunks/framework-2c79e2a64abdb08b.js", "x"));
        assertEquals("Framework / runtime chunk", C.classify("https://app.example/runtime.abc123.js", "x"));
    }

    @Test
    void bannerIdentifiesLibraryWithVersion() {
        String body = "/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors */!function(e,t){}";
        assertEquals("Library: jQuery 3.7.1", C.classify("https://app.example/static/lib.js", body));
    }

    @Test
    void appCodeStaysUntagged() {
        assertEquals("", C.classify("https://app.example/static/js/main.4f3a2b.js", "fetch('/api/users')"));
        assertEquals("", C.classify("https://app.example/_next/static/chunks/pages/_app-1234.js", "x"));
        assertEquals("", C.classify("https://app.example/js/react-app.js", "x"));
        assertEquals("", C.classify("import://admin-panel.js", "x"));
    }

    @Test
    void largeBodyIsNeverTaggedByBannerAlone() {
        // An app bundle that concatenates jQuery starts with jQuery's banner -- must not be hidden.
        String body = "/*! jQuery v3.7.1 */" + "x".repeat(JsLibraryClassifier.BANNER_MAX_BODY);
        assertEquals("", C.classify("https://app.example/static/bundle.js", body));
    }

    @Test
    void urlOnlyClassificationWorksWithoutBody() {
        assertEquals("Library: jQuery", C.classify("https://app.example/jquery.min.js", null));
        assertEquals("", C.classify("https://app.example/app.js", null));
    }
}
