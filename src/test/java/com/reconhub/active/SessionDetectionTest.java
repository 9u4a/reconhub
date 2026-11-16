package com.reconhub.active;

import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 0.60.0 session model: {@link AuthDetector}, {@link SessionDiscovery}, cookie / strip rules. Headless. */
class SessionDetectionTest {

    private static String jwt(String payloadJson) {
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        return enc.encodeToString("{\"alg\":\"HS256\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + enc.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8)) + ".s1gnature";
    }

    private static List<String[]> headers(String... nv) {
        List<String[]> out = new java.util.ArrayList<>();
        for (int i = 0; i < nv.length; i += 2) out.add(new String[]{nv[i], nv[i + 1]});
        return out;
    }

    // ---- AuthDetector -------------------------------------------------------------------

    @Test
    void sessionCookiesAndAuthHeadersAreConfirmedAnalyticsIgnored() {
        List<AuthDetector.Part> parts = AuthDetector.detect(headers(
                "Host", "app.example",
                "Cookie", "_ga=GA1.2.111; JSESSIONID=ABC123DEF; theme=dark; lang=ko",
                "Authorization", "Bearer abc",
                "X-Auth-Token", "t0k3n",
                "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 1234567890",
                "If-None-Match", "W/\"5f2a9c8b7e6d5c4b3a2f1e0d9c8b7a6f\""));
        assertEquals(List.of("JSESSIONID", "Authorization", "X-Auth-Token"),
                parts.stream().map(AuthDetector.Part::name).toList());
        assertTrue(parts.stream().allMatch(p -> p.confidence() == AuthDetector.Confidence.CONFIRMED));
    }

    @Test
    void unknownNamesWithTokenLikeValuesAreLikely() {
        List<AuthDetector.Part> parts = AuthDetector.detect(headers(
                "Cookie", "app_k=" + jwt("{\"sub\":\"a\"}") + "; counter=3",
                "X-Custom", "a8f3K2m9Q1z7X4c6V0b5N8a8f3K2m9Q1"));
        assertEquals(2, parts.size(), parts.toString());
        assertTrue(parts.stream().allMatch(p -> p.confidence() == AuthDetector.Confidence.LIKELY));
    }

    @Test
    void tokenInfoReadsSubjectAndExpiry() {
        AuthDetector.TokenInfo ti = AuthDetector.tokenInfo(List.of("x", "Bearer " + jwt("{\"email\":\"bob@x.example\",\"exp\":1000}")));
        assertNotNull(ti);
        assertEquals("email=bob@x.example", ti.subject());
        assertTrue(ti.expired(2000));
        assertNull(AuthDetector.tokenInfo(List.of("plain")));
    }

    @Test
    void pastedRequestBlockParses() {
        List<String[]> h = AuthDetector.parseHeaderBlock("GET /api/me HTTP/1.1\r\nHost: a\r\nCookie: sid=1\r\n\r\n{\"x\":1}");
        assertEquals(2, h.size());
        assertEquals("Cookie", h.get(1)[0]);
    }

    // ---- rules ----------------------------------------------------------------------------

    @Test
    void cookieRulesTouchOnlyTheNamedCookie() {
        MatchReplaceRule set = MatchReplaceRule.cookie("sid", "B");
        assertEquals("a=1; sid=B; z=2", set.computeCookieHeader("a=1; sid=A; z=2"));
        assertEquals("a=1; sid=B", set.computeCookieHeader("a=1"));
        MatchReplaceRule rm = MatchReplaceRule.removeCookie("sid");
        assertEquals("a=1", rm.computeCookieHeader("sid=A; a=1"));
        assertEquals("", rm.computeCookieHeader("sid=A"));            // last cookie gone -> drop header
        assertNull(rm.computeCookieHeader(null));                     // nothing to do
    }

    @Test
    void stripPlanKeepsTheIdentitysOwnParts() {
        List<String>[] plan = AuthDetector.stripPlan(headers(
                "Cookie", "JSESSIONID=A; PHPSESSID=X; _ga=1",
                "Authorization", "Bearer A",
                "X-Api-Key", "k"), Set.of("authorization"), Set.of("JSESSIONID"));
        assertEquals(List.of("X-Api-Key"), plan[0]);
        assertEquals(List.of("PHPSESSID"), plan[1]);
    }

    // ---- discovery ------------------------------------------------------------------------

    @Test
    void discoveryGroupsByCredentialValuesIgnoringCsrf() {
        String aliceJwt = jwt("{\"sub\":\"alice\"}");
        List<SessionDiscovery.Sample> samples = List.of(
                new SessionDiscovery.Sample("app.example", "/a", headers("Authorization", "Bearer " + aliceJwt, "X-CSRF-Token", "1"), 10),
                new SessionDiscovery.Sample("app.example", "/b", headers("Authorization", "Bearer " + aliceJwt, "X-CSRF-Token", "2"), 20),
                new SessionDiscovery.Sample("app.example", "/c", headers("Cookie", "JSESSIONID=BOB; _ga=1"), 30),
                new SessionDiscovery.Sample("app.example", "/d", headers("Accept", "*/*"), 40));
        SessionProfiles.Identity saved = new SessionProfiles.Identity("bob", Map.of(), Map.of("JSESSIONID", "BOB"), "t", 0);
        List<SessionDiscovery.Candidate> c = SessionDiscovery.discover(samples, List.of(saved));
        assertEquals(2, c.size(), c.toString());
        SessionDiscovery.Candidate alice = c.stream().filter(x -> x.headers().containsKey("Authorization")).findFirst().orElseThrow();
        assertEquals(2, alice.requests());
        assertEquals("/b", alice.samplePath());
        assertEquals("2", alice.headers().get("X-CSRF-Token"), "latest CSRF value kept");
        assertEquals("sub=alice", alice.token().subject());
        assertEquals("", alice.registeredAs());
        SessionDiscovery.Candidate bob = c.stream().filter(x -> x.cookies().containsKey("JSESSIONID")).findFirst().orElseThrow();
        assertEquals("bob", bob.registeredAs());
        assertFalse(bob.cookies().containsKey("_ga"));
    }

    @Test
    void storeNamesListenersAndBuiltIns() {
        SessionProfiles s = new SessionProfiles();
        int[] fired = {0};
        s.addListener(() -> fired[0]++);
        s.put(new SessionProfiles.Identity("user", Map.of("Authorization", "B"), Map.of(), "t", 0));
        assertEquals("user 2", s.uniqueName("user"));
        assertTrue(s.rename("user", "user B"));
        assertNull(s.get("user"));
        assertEquals(List.of(), s.rulesForName(SessionProfiles.ORIGINAL));
        assertEquals(3, s.rulesForName(SessionProfiles.NO_AUTH).size());
        assertNull(s.rulesForName("nobody"));
        s.remove("user B");
        assertEquals(3, fired[0]);
    }
}
