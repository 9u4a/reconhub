package com.reconhub.analysis;

import com.reconhub.model.Finding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** CSRF / upload / auth-flow leads (0.57.0) against the shipped leads.json. */
class RequestLeadsTest {

    private static final PatternRegistry.LeadRules R = PatternRegistry.load().leadRules();
    private static final String URL = "https://h.example/api/profile/update";

    private static Finding csrf(String method, boolean cookie, boolean auth, List<String> headers,
                                List<String> params, String ct) {
        return RequestLeads.csrf(method, "/api/profile/update", URL, 200, cookie, auth, headers, params, ct, R);
    }

    @Test
    void cookieFormPostWithoutTokenIsACsrfCandidate() {
        Finding f = csrf("POST", true, false, List.of("Host", "Cookie", "Content-Type"), List.of("nickname"),
                "application/x-www-form-urlencoded");
        assertNotNull(f);
        assertEquals(RequestLeads.CSRF_TYPE, f.getType());
        assertEquals(Finding.Severity.LOW, f.getSeverity());
        assertEquals("POST " + URL, f.getRawMatch());
        assertTrue(f.getEvidence().contains("Try:"));
        assertEquals(FindingTaxonomy.Category.AUTH, FindingTaxonomy.categoryOf(f.getType()));
    }

    @Test
    void jsonIsInfoOnly() {
        Finding f = csrf("POST", true, false, List.of("Cookie"), List.of("nickname"), "application/json");
        assertEquals(Finding.Severity.INFO, f.getSeverity());
    }

    @Test
    void protectedOrNonCookieRequestsAreNotCandidates() {
        String form = "application/x-www-form-urlencoded";
        assertNull(csrf("POST", true, false, List.of("Cookie"), List.of("_csrf", "nickname"), form));
        assertNull(csrf("POST", true, false, List.of("Cookie"), List.of("CSRFToken"), form));
        assertNull(csrf("POST", true, false, List.of("Cookie", "X-XSRF-TOKEN"), List.of(), form));
        assertNull(csrf("POST", true, false, List.of("Cookie", "X-Requested-With"), List.of(), form));
        assertNull(csrf("POST", true, true, List.of("Cookie"), List.of(), form));   // bearer auth
        assertNull(csrf("POST", false, false, List.of(), List.of(), form));          // no cookie
        assertNull(csrf("GET", true, false, List.of("Cookie"), List.of(), form));
        assertNull(csrf("POST", true, false, List.of("Cookie"), List.of(), "application/xml"));
        // login CSRF is skipped
        assertNull(RequestLeads.csrf("POST", "/member/login.do", "https://h.example/member/login.do", 200, true,
                false, List.of("Cookie"), List.of("id", "pw"), form, R));
    }

    @Test
    void multipartFilePartIsAnUploadEndpoint() {
        String body = "------x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"cv.pdf\"\r\n"
                + "Content-Type: application/pdf\r\n\r\n%PDF";
        Finding f = RequestLeads.upload("POST", URL, "multipart/form-data; boundary=----x", body);
        assertNotNull(f);
        assertTrue(f.getEvidence().contains("cv.pdf"), f.getEvidence());
        assertNull(RequestLeads.upload("POST", URL, "multipart/form-data; boundary=----x",
                "------x\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello"));
        assertNull(RequestLeads.upload("POST", URL, "application/json", body));
    }

    @Test
    void authFlowFamilies() {
        assertEquals("Auth flow endpoint: login", flow("/member/login.do").getType());
        assertEquals("Auth flow endpoint: login", flow("/api/v1/auth/signin").getType());
        assertEquals("Auth flow endpoint: OTP / MFA", flow("/api/otp/verify").getType());
        assertEquals("Auth flow endpoint: password reset", flow("/user/findPw").getType());
        assertEquals("Auth flow endpoint: password reset", flow("/api/password/reset").getType());
        assertEquals("Auth flow endpoint: signup", flow("/member/join").getType());
        assertEquals("Auth flow endpoint: token refresh", flow("/oauth/token").getType());
        assertNull(flow("/api/products/123"));
        assertNull(flow("/blog/joined-teams"));
        assertNull(RequestLeads.authFlow("GET", "/member/login.do", "u", 200, List.of(), R));
        assertEquals(FindingTaxonomy.Category.AUTH, FindingTaxonomy.categoryOf("Auth flow endpoint: login"));
    }

    @Test
    void rateLimitHeaderIsNoted() {
        assertTrue(flow("/login").getEvidence().contains("no rate-limit header"));
        Finding limited = RequestLeads.authFlow("POST", "/login", "u", 200, List.of("X-RateLimit-Remaining"), R);
        assertTrue(!limited.getEvidence().contains("no rate-limit header"), limited.getEvidence());
    }

    private static Finding flow(String path) {
        return RequestLeads.authFlow("POST", path, "https://h.example" + path, 200, List.of("Content-Type"), R);
    }
}
