package com.reconhub.analysis;

import com.reconhub.model.Finding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Mass assignment / sensitive response field leads (0.57.0). */
class BodyLeadsTest {

    private static final PatternRegistry.LeadRules R = PatternRegistry.load().leadRules();
    private static final String URL = "https://h.example/api/users/me";
    private static final String JSON = "application/json; charset=utf-8";

    private static List<Finding> scan(String method, String req, String resp) {
        return BodyLeads.scan(method, URL, 200, JSON, req, JSON, resp, R);
    }

    private static List<String> types(List<Finding> fs) {
        return fs.stream().map(Finding::getType).toList();
    }

    @Test
    void privilegedResponseFieldNotSentIsAMassAssignmentCandidate() {
        List<String> t = types(scan("PUT", "{\"nickname\":\"a\"}",
                "{\"data\":{\"id\":7,\"nickname\":\"a\",\"role\":\"USER\",\"isAdmin\":false}}"));
        assertTrue(t.contains("Mass assignment candidate: role"), t.toString());
        assertTrue(t.contains("Mass assignment candidate: isAdmin"), t.toString());
        assertEquals(FindingTaxonomy.Category.AUTH, FindingTaxonomy.categoryOf("Mass assignment candidate: role"));
    }

    @Test
    void notWhenAlreadySentNotOnGetAndNotDeepInsideArrays() {
        assertFalse(types(scan("PUT", "{\"user_role\":\"USER\"}", "{\"userRole\":\"USER\"}"))
                .contains("Mass assignment candidate: userRole"));
        assertTrue(scan("GET", null, "{\"role\":\"USER\"}").isEmpty());
        // a search result list: price of each product is not this request's object
        assertTrue(scan("POST", "{\"q\":\"shoes\"}", "{\"items\":[{\"name\":\"x\",\"price\":10}]}").isEmpty());
        assertTrue(scan("POST", "{\"q\":\"shoes\"}", "[{\"role\":\"x\"}]").isEmpty());
    }

    @Test
    void sensitiveFieldWithValueIsFlaggedWithoutTheValue() {
        List<Finding> fs = scan("GET", null, "{\"id\":1,\"password\":\"$2a$10$abcdefghijk\",\"pin\":\"\"}");
        assertEquals(1, fs.size(), types(fs).toString());
        Finding f = fs.get(0);
        assertEquals("Sensitive field in response: password", f.getType());
        assertEquals(Finding.Severity.MEDIUM, f.getSeverity());
        assertFalse(f.getEvidence().contains("abcdefghijk"));
        assertEquals(FindingTaxonomy.Category.PII, FindingTaxonomy.categoryOf(f.getType()));
        assertTrue(scan("GET", null, "{\"password\":\"********\"}").isEmpty());
        assertTrue(scan("GET", null, "{\"password\":null,\"secret\":true}").isEmpty());
    }

    @Test
    void nonJsonOrErrorResponsesAreIgnored() {
        assertTrue(BodyLeads.scan("GET", URL, 200, null, null, "text/html", "{\"password\":\"x\"}", R).isEmpty());
        assertTrue(BodyLeads.scan("GET", URL, 500, null, null, JSON, "{\"password\":\"x\"}", R).isEmpty());
        assertTrue(scan("GET", null, "not json at all").isEmpty());
        assertTrue(scan("GET", null, "{\"password\":\"abc\"").size() == 1);   // truncated: keeps what was read
    }

    @Test
    void hostileBodiesAreBounded() {
        String deep = "[".repeat(200_000);
        assertTrue(BodyLeads.fields(deep).all().isEmpty());
        StringBuilder many = new StringBuilder("{");
        for (int i = 0; i < 10_000; i++) {
            many.append("\"k").append(i).append("\":1,");
        }
        many.append("\"z\":1}");
        assertEquals(BodyLeads.MAX_KEYS, BodyLeads.fields(many.toString()).all().size());
        assertTrue(BodyLeads.fields("{\"a\":\"" + "x".repeat(BodyLeads.MAX_BODY) + "\"}").all().isEmpty());
    }
}
