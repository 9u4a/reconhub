package com.reconhub.active;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Authz verdict of a Match & Replace resend (0.57.0) and the session presets' rule chains. */
class ResponseCompareTest {

    private static ResponseCompare.Verdict v(int os, String ob, int ns, String nb, String loc) {
        return ResponseCompare.compare(os, ob, ob == null ? 0 : ob.length(), ns, nb, nb == null ? 0 : nb.length(),
                loc).verdict();
    }

    @Test
    void sameDataDespiteDynamicTokensIsSame() {
        String a = "{\"id\":42,\"name\":\"Alice\",\"email\":\"a@mail.example\",\"ts\":1730000000123,"
                + "\"csrf\":\"0123456789abcdef0123456789abcdef\"}";
        String b = "{\"id\":42,\"name\":\"Alice\",\"email\":\"a@mail.example\",\"ts\":1730000099999,"
                + "\"csrf\":\"fedcba9876543210fedcba9876543210\"}";
        assertEquals(ResponseCompare.Verdict.SAME, v(200, a, 200, b, null));
    }

    @Test
    void refusedIsBlocked() {
        assertEquals(ResponseCompare.Verdict.BLOCKED, v(200, "{\"id\":1}", 403, "Forbidden", null));
        assertEquals(ResponseCompare.Verdict.BLOCKED, v(200, "{\"id\":1}", 401, "", null));
        assertEquals(ResponseCompare.Verdict.BLOCKED, v(200, "{\"id\":1}", 302, "", "/member/login.do?next=/x"));
    }

    @Test
    void otherDataOrStatusIsDifferent() {
        assertEquals(ResponseCompare.Verdict.DIFFERENT, v(200, "{\"id\":1,\"name\":\"Alice\",\"orders\":[1,2,3]}",
                200, "{\"error\":\"not found\"}", null));
        assertEquals(ResponseCompare.Verdict.DIFFERENT, v(200, "ok", 500, "ok", null));
        assertEquals(ResponseCompare.Verdict.DIFFERENT, v(200, "{\"id\":1}", 302, "", "/home"));
    }

    @Test
    void notComparableWithoutBothResponses() {
        ResponseCompare.Result r = ResponseCompare.compare(0, null, 0, 200, "x", 1, null);
        assertEquals(ResponseCompare.Verdict.NA, r.verdict());
        assertEquals(ResponseCompare.Verdict.NA, v(200, "x", 0, null, null));
    }

    @Test
    void similarityBounds() {
        assertEquals(1.0, ResponseCompare.similarity("", ""));
        assertEquals(0.0, ResponseCompare.similarity("abc", ""));
        assertTrue(ResponseCompare.similarity("a\nb\nc", "a\nb\nc") > 0.99);
        String big = "x,".repeat(400_000);
        assertTrue(ResponseCompare.similarity(big, big) > 0.99);
    }

    @Test
    void sessionPresetsReplaceOrRemoveBothCredentialHeaders() {
        List<MatchReplaceRule> off = SessionProfiles.removeAuthRules();
        assertEquals(2, off.size());
        assertTrue(off.stream().allMatch(r -> r.mode() == MatchReplaceRule.Mode.REMOVE_HEADER));
        assertNull(off.get(0).regexError());

        SessionProfiles s = new SessionProfiles();
        s.put(new SessionProfiles.Profile(" user B ", "sid=bbb", "  "));
        s.put(new SessionProfiles.Profile("", "x", "y"));   // ignored
        assertEquals(1, s.list().size());
        List<MatchReplaceRule> b = SessionProfiles.rulesFor(s.get("user B"));
        assertEquals(MatchReplaceRule.Mode.HEADER, b.get(0).mode());
        assertEquals("Cookie", b.get(0).headerName());
        assertEquals("sid=bbb", b.get(0).computeHeaderValue("sid=aaa"));
        assertEquals("sid=bbb", b.get(0).computeHeaderValue(null));   // added if missing
        assertEquals(MatchReplaceRule.Mode.REMOVE_HEADER, b.get(1).mode());   // blank Authorization -> removed
    }
}
