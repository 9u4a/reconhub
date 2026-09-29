package com.reconhub.ui;

import com.reconhub.core.DataStore;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code RunBruteforceAction.inferScheme}/{@code schemesByHost} -- 0.41.0 split a single-host linear
 * scan into a reusable one-pass-over-all-hosts version, with {@code inferScheme} now delegating to it.
 * Pure logic against a real {@link DataStore} (no Montoya object-factory calls), headless. */
class RunBruteforceActionTest {

    private static DataStore populated() {
        DataStore store = new DataStore();
        store.recordEndpoint("GET", "http.example", "/a", "http://http.example/a", 200, "text/html",
                "sitemap", Set.of(), null, Set.of());
        store.recordEndpoint("GET", "https.example", "/a", "https://https.example/a", 200, "text/html",
                "sitemap", Set.of(), null, Set.of());
        // both.example: first-recorded endpoint is http -- "first match wins" per inferScheme's
        // original linear-scan semantics, which schemesByHost's putIfAbsent must reproduce.
        store.recordEndpoint("GET", "both.example", "/a", "http://both.example/a", 200, "text/html",
                "sitemap", Set.of(), null, Set.of());
        store.recordEndpoint("GET", "both.example", "/b", "https://both.example/b", 200, "text/html",
                "sitemap", Set.of(), null, Set.of());
        return store;
    }

    // ---- inferScheme (single host) -------------------------------------------------------------

    @Test
    void inferSchemeReturnsHttpForAHostOnlyEverSeenOverHttp() {
        assertEquals("http", RunBruteforceAction.inferScheme(populated(), "http.example"));
    }

    @Test
    void inferSchemeReturnsHttpsForAHostOnlyEverSeenOverHttps() {
        assertEquals("https", RunBruteforceAction.inferScheme(populated(), "https.example"));
    }

    @Test
    void inferSchemeDefaultsToHttpsForAnUnknownHost() {
        assertEquals("https", RunBruteforceAction.inferScheme(populated(), "never-seen.example"));
    }

    @Test
    void inferSchemeIsCaseInsensitiveOnHost() {
        assertEquals("http", RunBruteforceAction.inferScheme(populated(), "HTTP.EXAMPLE"));
    }

    @Test
    void inferSchemeHandlesNullStoreOrHost() {
        assertEquals("https", RunBruteforceAction.inferScheme(null, "http.example"));
        assertEquals("https", RunBruteforceAction.inferScheme(populated(), null));
    }

    @Test
    void inferSchemeFirstMatchWinsWhenBothSchemesAreObservedForOneHost() {
        assertEquals("http", RunBruteforceAction.inferScheme(populated(), "both.example"));
    }

    // ---- schemesByHost (bulk) -------------------------------------------------------------------

    @Test
    void schemesByHostComputesEveryHostInOnePass() {
        Map<String, String> schemes = RunBruteforceAction.schemesByHost(populated());
        assertEquals("http", schemes.get("http.example"));
        assertEquals("https", schemes.get("https.example"));
        assertEquals("http", schemes.get("both.example"));
        assertEquals(3, schemes.size());
    }

    @Test
    void schemesByHostKeysByLowerCasedHost() {
        Map<String, String> schemes = RunBruteforceAction.schemesByHost(populated());
        assertTrue(schemes.containsKey("http.example"));
        assertEquals("http", schemes.getOrDefault("HTTP.EXAMPLE".toLowerCase(java.util.Locale.ROOT), null));
    }

    @Test
    void schemesByHostOnNullOrEmptyStoreIsAnEmptyMap() {
        assertTrue(RunBruteforceAction.schemesByHost(null).isEmpty());
        assertTrue(RunBruteforceAction.schemesByHost(new DataStore()).isEmpty());
    }

    @Test
    void inferSchemeAndSchemesByHostAgreeForEveryHost() {
        // Regression guard: inferScheme delegates to schemesByHost -- they must never answer
        // differently for the same host.
        DataStore store = populated();
        Map<String, String> schemes = RunBruteforceAction.schemesByHost(store);
        for (String host : Set.of("http.example", "https.example", "both.example", "unknown.example")) {
            String expected = schemes.getOrDefault(host, "https");
            assertEquals(expected, RunBruteforceAction.inferScheme(store, host));
        }
    }
}
