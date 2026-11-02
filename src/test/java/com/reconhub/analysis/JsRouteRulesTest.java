package com.reconhub.analysis;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/** Sensitive-route detection (0.55.0): {@code JsAnalyzer.routeRuleFor}/{@code routePath} against the
 * shipped js-routes.json. Pure logic, headless. */
class JsRouteRulesTest {

    private static final List<PatternRegistry.SecretRule> RULES = PatternRegistry.load().jsRouteRules();

    private static String family(String link) {
        PatternRegistry.SecretRule r = JsAnalyzer.routeRuleFor(link, RULES);
        return r == null ? null : r.name.substring(r.name.indexOf(':') + 2);
    }

    @Test
    void routePathNormalizes() {
        assertEquals("/admin/users", JsAnalyzer.routePath("https://h.example/admin/users/?x=1#top"));
        assertEquals("/api/v1/export", JsAnalyzer.routePath("api/v1/export"));
        assertEquals("/x", JsAnalyzer.routePath("//cdn.example/x"));
        assertEquals("/", JsAnalyzer.routePath("https://h.example"));
        assertEquals("/a", JsAnalyzer.routePath("./a"));
    }

    @Test
    void sensitiveFamiliesMatch() {
        assertEquals("admin", family("/admin/users"));
        assertEquals("admin", family("https://h.example/backoffice/login"));
        assertEquals("actuator/diagnostic", family("/actuator/env"));
        assertEquals("upload", family("/api/file-upload"));
        assertEquals("object by id", family("/api/users/1234"));
        assertEquals("object by id", family("/orders/:orderId/items"));
        assertEquals("export/download", family("/report/export?from=2024"));
        assertEquals("GraphQL", family("/graphql"));
        assertEquals("config/secrets", family("/static/config.json"));
    }

    @Test
    void ordinaryAndStaticPathsDoNotMatch() {
        assertNull(family("/api/products"));
        assertNull(family("/login"));
        assertNull(family("/administration-guide-not-a-route-ish"));
        assertNull(family("/admin/css/app.css"));
        assertNull(family("/admin/app.js"));
        assertNull(family("/users"));
        assertNull(family("/user/settings"));
    }
}
