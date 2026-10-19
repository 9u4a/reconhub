package com.reconhub.core;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code Hosts.inferScheme}/{@code schemesByHost} -- the scheme-inference helpers used by
 * Dashboard/Tech/Settings to avoid defaulting to https:// against a host only ever seen over http.
 * (Moved here in 0.46.0 from the removed {@code ui.RunBruteforceAction}; logic unchanged.)
 */
class HostsSchemeTest {

    private static DataStore populated() {
        DataStore store = new DataStore();
        store.recordEndpoint("GET", "http.example", "/a", "http://http.example/a", 200, "text/html",
                "sitemap", Set.of(), null, Set.of());
        store.recordEndpoint("GET", "https.example", "/a", "https://https.example/a", 200, "text/html",
                "sitemap", Set.of(), null, Set.of());
        // both.example: first-recorded endpoint is http -- "first match wins", which schemesByHost's
        // putIfAbsent must reproduce.
        store.recordEndpoint("GET", "both.example", "/http", "http://both.example/http", 200, "text/html",
                "sitemap", Set.of(), null, Set.of());
        store.recordEndpoint("GET", "both.example", "/https", "https://both.example/https", 200, "text/html",
                "sitemap", Set.of(), null, Set.of());
        return store;
    }

    @Test
    void inferSchemeReturnsHttpForAHostOnlyEverSeenOverHttp() {
        assertEquals("http", Hosts.inferScheme(populated(), "http.example"));
    }

    @Test
    void inferSchemeReturnsHttpsForAHostOnlyEverSeenOverHttps() {
        assertEquals("https", Hosts.inferScheme(populated(), "https.example"));
    }

    @Test
    void inferSchemeDefaultsToHttpsForAnUnknownHost() {
        assertEquals("https", Hosts.inferScheme(populated(), "never-seen.example"));
    }

    @Test
    void inferSchemeIsCaseInsensitiveOnHost() {
        assertEquals("http", Hosts.inferScheme(populated(), "HTTP.EXAMPLE"));
    }

    @Test
    void inferSchemeHandlesNullStoreOrHost() {
        assertEquals("https", Hosts.inferScheme(null, "http.example"));
        assertEquals("https", Hosts.inferScheme(populated(), null));
    }

    @Test
    void inferSchemeFirstMatchWinsWhenBothSchemesAreObservedForOneHost() {
        assertEquals("http", Hosts.inferScheme(populated(), "both.example"));
    }

    @Test
    void schemesByHostComputesEveryHostInOnePass() {
        Map<String, String> schemes = Hosts.schemesByHost(populated());
        assertEquals("http", schemes.get("http.example"));
        assertEquals("https", schemes.get("https.example"));
        assertEquals("http", schemes.get("both.example"));
    }

    @Test
    void schemesByHostKeysByLowerCasedHost() {
        Map<String, String> schemes = Hosts.schemesByHost(populated());
        assertTrue(schemes.containsKey("http.example"));
    }

    @Test
    void schemesByHostOnNullOrEmptyStoreIsAnEmptyMap() {
        assertTrue(Hosts.schemesByHost(null).isEmpty());
        assertTrue(Hosts.schemesByHost(new DataStore()).isEmpty());
    }

    @Test
    void inferSchemeAndSchemesByHostAgreeForEveryHost() {
        DataStore store = populated();
        Map<String, String> schemes = Hosts.schemesByHost(store);
        for (String host : schemes.keySet()) {
            assertEquals(schemes.get(host), Hosts.inferScheme(store, host));
        }
    }
}
