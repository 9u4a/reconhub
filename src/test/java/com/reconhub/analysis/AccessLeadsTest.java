package com.reconhub.analysis;

import com.reconhub.model.Finding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Unauthenticated-access leads (0.56.0): {@code AccessLeads.lead} against the shipped js-routes.json. */
class AccessLeadsTest {

    private static final List<PatternRegistry.SecretRule> ROUTES = PatternRegistry.load().jsRouteRules();

    private static Finding lead(boolean authed, int status, String method, String path, String ct) {
        return AccessLeads.lead(authed, status, method, path, "https://h.example" + path, ct, ROUTES);
    }

    @Test
    void anonymousJsonApiIsALowLead() {
        Finding f = lead(false, 200, "GET", "/api/orders", "application/json; charset=utf-8");
        assertNotNull(f);
        assertEquals("Unauthenticated access: API", f.getType());
        assertEquals(Finding.Severity.LOW, f.getSeverity());
        assertTrue(f.getEvidence().contains("Try:"), f.getEvidence());
        assertEquals(FindingTaxonomy.Category.AUTH, FindingTaxonomy.categoryOf(f.getType()));
    }

    @Test
    void anonymousSensitiveRouteIsAMediumLeadNamedByFamily() {
        Finding f = lead(false, 200, "GET", "/admin/users", "text/html");
        assertNotNull(f);
        assertEquals("Unauthenticated access: admin", f.getType());
        assertEquals(Finding.Severity.MEDIUM, f.getSeverity());
    }

    @Test
    void notALead() {
        assertNull(lead(false, 200, "GET", "/about", "text/html"), "public HTML page");
        assertNull(lead(true, 200, "GET", "/api/orders", "application/json"), "authed observation");
        assertNull(lead(false, 401, "GET", "/api/orders", "application/json"), "rejected");
        assertNull(lead(false, 302, "GET", "/admin", "text/html"), "redirect to login");
        assertNull(lead(false, 204, "POST", "/api/ping", "application/json"), "no content");
        assertNull(lead(false, 200, "OPTIONS", "/api/orders", "application/json"), "preflight");
        assertNull(lead(false, 200, "GET", "/static/app.js", "application/javascript"), "static asset");
    }

    @Test
    void oneFindingPerEndpoint() {
        Finding a = lead(false, 200, "GET", "/api/orders", "application/json");
        Finding b = lead(false, 201, "GET", "/api/orders", "application/json");
        assertEquals(a.key(), b.key());
    }
}
