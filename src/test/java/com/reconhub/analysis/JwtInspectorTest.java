package com.reconhub.analysis;

import com.reconhub.core.DataStore;
import com.reconhub.model.Finding;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** JWT weakness findings (0.57.0). */
class JwtInspectorTest {

    private static final PatternRegistry.LeadRules R = PatternRegistry.load().leadRules();
    private static final long NOW = 1_800_000_000L;

    static String jwt(String header, String payload, String sig) {
        Base64.Encoder e = Base64.getUrlEncoder().withoutPadding();
        return e.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "."
                + e.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + "." + sig;
    }

    private static Set<String> labels(String token) {
        return new java.util.HashSet<>(JwtInspector.issues(JwtDecoder.parse(token), R, NOW).stream()
                .map(JwtInspector.Issue::label).toList());
    }

    @Test
    void issues() {
        assertTrue(labels(jwt("{\"alg\":\"none\"}", "{\"sub\":\"1\",\"exp\":1800000100}", ""))
                .contains("alg=none"));
        Set<String> hs = labels(jwt("{\"alg\":\"HS256\",\"kid\":\"k1\"}", "{\"sub\":\"1\"}", "abcdefgh"));
        assertTrue(hs.containsAll(Set.of("symmetric HS256", "kid header", "no expiry (exp)")), hs.toString());
        assertTrue(labels(jwt("{\"alg\":\"RS256\",\"jku\":\"https://k.example/jwks\"}",
                "{\"exp\":1800000100}", "abcdefgh")).contains("embedded key / key URL (jku, x5u, jwk)"));
        assertTrue(labels(jwt("{\"alg\":\"RS256\"}", "{\"iat\":1700000000,\"exp\":1800000000}", "abcdefgh"))
                .contains("long-lived token"));
        Set<String> claims = labels(jwt("{\"alg\":\"RS256\"}",
                "{\"exp\":1800000100,\"password\":\"x\",\"role\":\"user\"}", "abcdefgh"));
        assertTrue(claims.containsAll(Set.of("sensitive claim", "privilege claim")), claims.toString());
        assertTrue(labels(jwt("{\"alg\":\"RS256\"}", "{\"sub\":\"1\",\"iat\":1799999000,\"exp\":1800000100}",
                "abcdefgh")).isEmpty());
    }

    @Test
    void summaryNamesClaimsButNeverValues() {
        String s = JwtInspector.summary(JwtDecoder.parse(jwt("{\"alg\":\"HS256\",\"kid\":\"k\"}",
                "{\"email\":\"someone@mail.example\"}", "abcdefgh")));
        assertTrue(s.contains("alg=HS256") && s.contains("kid") && s.contains("email"), s);
        assertFalse(s.contains("someone@"), s);
    }

    @Test
    void tokensAreFoundInHeadersAndBodies() {
        String t = jwt("{\"alg\":\"none\"}", "{\"sub\":\"12345\"}", "");
        Set<String> found = JwtInspector.tokensIn(List.of("Bearer " + t, "a=1; sid=x", "{\"x\":1}"));
        assertEquals(Set.of(t), found);
    }

    @Test
    void oneFindingPerHostAndIssueUntilItIsGone() {
        DataStore store = new DataStore();
        JwtInspector inspector = new JwtInspector(store, R);
        String a = jwt("{\"alg\":\"HS256\"}", "{\"sub\":\"1\",\"exp\":1900000000,\"iat\":1899999000}", "aaaaaaaa");
        String b = jwt("{\"alg\":\"HS256\"}", "{\"sub\":\"2\",\"exp\":1900000000,\"iat\":1899999000}", "bbbbbbbb");
        inspector.inspect("h.example", "https://h.example/a", List.of("Bearer " + a), null);
        inspector.inspect("h.example", "https://h.example/b", List.of("Bearer " + b), null);
        List<Finding> fs = store.snapshotFindings();
        assertEquals(1, fs.size(), fs.stream().map(Finding::getType).toList().toString());
        assertEquals("JWT weakness: symmetric HS256", fs.get(0).getType());
        assertEquals(FindingTaxonomy.Category.SECRET, FindingTaxonomy.categoryOf(fs.get(0).getType()));
        store.clear();
        inspector.inspect("h.example", "https://h.example/b", List.of("Bearer " + b), null);
        assertEquals(1, store.snapshotFindings().size());
    }
}
