package com.reconhub.analysis;

import org.junit.jupiter.api.Test;

import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The 0.47.0 JS deep-analysis rule sets ({@code js-crypto/authz/sinks/config.json}): representative
 * real snippets match, obvious non-matches don't, and each rule's name classifies into the intended
 * {@link FindingTaxonomy.Category}. Pure regex + string logic (no Montoya), headless.
 */
class JsAnalysisRulesTest {

    private static final PatternRegistry REGISTRY = PatternRegistry.load();

    private static boolean anyMatch(String body) {
        for (PatternRegistry.SecretRule r : REGISTRY.jsFindingRules()) {
            if (r.pattern.matcher(body).find()) {
                return true;
            }
        }
        return false;
    }

    /** The name of the first jsFindingRule that matches {@code body}, or null. */
    private static String firstMatchName(String body) {
        for (PatternRegistry.SecretRule r : REGISTRY.jsFindingRules()) {
            if (r.pattern.matcher(body).find()) {
                return r.name;
            }
        }
        return null;
    }

    @Test
    void rulesLoadedFromAllFiles() {
        // 0.52.0: 9 crypto + 5 authz + 3 config + 3 api-auth = 20 jsFindingRules (sinks moved to
        // js-flow). Assert a healthy floor so a silently-dropped file (bad JSON) fails the build.
        assertTrue(REGISTRY.jsFindingRules().size() >= 16,
                "expected the JS rule files to load, got " + REGISTRY.jsFindingRules().size());
    }

    @Test
    void cryptoSnippetsMatchAndClassifyAsCrypto() {
        for (String snippet : new String[]{
                "var e = CryptoJS.AES.encrypt(msg, key);",
                "await crypto.subtle.encrypt(alg, k, data)",
                "var enc = new JSEncrypt(); enc.setPublicKey(pk);",
                "atob(token)",
                "cipher: \"AES-128-ECB\"",
                "var passphrase = \"s3cr3tPassphrase\";"}) {
            String name = firstMatchName(snippet);
            assertTrue(name != null, "should match a crypto rule: " + snippet);
            assertEquals(FindingTaxonomy.Category.CRYPTO, FindingTaxonomy.categoryOf(name),
                    "wrong category for [" + name + "] from: " + snippet);
        }
    }

    @Test
    void authzSnippetsMatchAndClassifyAsAuth() {
        for (String snippet : new String[]{
                "if (user.isAdmin()) { showPanel(); }",
                "if (role === 'admin') render();",
                "export const AdminRoute = requireRole('admin');",
                "const permissions = ['read','write'];",
                "adminOnly = true"}) {
            String name = firstMatchName(snippet);
            assertTrue(name != null, "should match an authz rule: " + snippet);
            assertEquals(FindingTaxonomy.Category.AUTH, FindingTaxonomy.categoryOf(name),
                    "wrong category for [" + name + "] from: " + snippet);
        }
    }

    @Test
    void configSnippetsMatchAndClassifyAsInfoLeak() {
        for (String snippet : new String[]{
                "fetch('https://api.staging.example.com/v1/users')",
                "apiBaseUrl: \"https://internal-api.corp.example/\"",
                "https://my-bucket.s3.us-east-1.amazonaws.com/key"}) {
            String name = firstMatchName(snippet);
            assertTrue(name != null, "should match a config rule: " + snippet);
            assertEquals(FindingTaxonomy.Category.INFO_LEAK, FindingTaxonomy.categoryOf(name),
                    "wrong category for [" + name + "] from: " + snippet);
        }
    }

    @Test
    void apiAuthSnippetsMatchAndClassifyAsApi() {
        // 0.52.0: the js-api-calls set is trimmed to auth-bearing signals only (generic fetch/axios
        // inventory was dropped as noise).
        for (String snippet : new String[]{
                "xhr.setRequestHeader('Authorization', 'Bearer ' + t);",
                "headers: { Authorization: `Bearer ${token}` }",
                "headers: { 'X-API-Key': 'abc' }"}) {
            String name = firstMatchName(snippet);
            assertTrue(name != null, "should match an API-auth rule: " + snippet);
            assertEquals(FindingTaxonomy.Category.API, FindingTaxonomy.categoryOf(name),
                    "wrong category for [" + name + "] from: " + snippet);
        }
    }

    @Test
    void genericApiInventoryNoLongerFlagged() {
        // The noisy generic-call signals were removed in 0.52.0 (moved value to js-flow / dropped).
        assertFalse(anyMatch("fetch('/api/users', { method: 'POST' })"));
        assertFalse(anyMatch("axios.get('/api/data')"));
    }

    @Test
    void plainBoringCodeMatchesNothing() {
        assertFalse(anyMatch("function add(a, b) { return a + b; }"));
        assertFalse(anyMatch("const total = items.reduce((s, x) => s + x.price, 0);"));
    }

    @Test
    void everyJsRuleCompiles() {
        // Loading already compiles them; assert load produced no error entries for the JS files.
        for (String err : REGISTRY.loadErrors()) {
            assertFalse(err.contains("js-crypto") || err.contains("js-authz")
                    || err.contains("js-config") || err.contains("js-api-calls")
                    || err.contains("js-flow"), "rule load error: " + err);
        }
        // sanity: patterns are non-null
        for (PatternRegistry.SecretRule r : REGISTRY.jsFindingRules()) {
            assertTrue(r.pattern instanceof Pattern);
        }
    }
}
