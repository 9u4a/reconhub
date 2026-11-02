package com.reconhub.analysis;

import com.reconhub.model.Finding;

import java.util.List;
import java.util.Locale;

/**
 * Passive access-control lead (0.56.0): an observation that carried <b>no</b> credentials (no
 * Authorization, no Cookie) yet got a 2xx back from an API response or a sensitive-looking route. Precision
 * over recall -- any cookie counts as "authed", so anonymous observations are rare and the ones that answered
 * with data are worth a replay. Pure/static for headless testing; never sends anything.
 */
public final class AccessLeads {

    public static final String TYPE_PREFIX = "Unauthenticated access: ";
    static final String API_LABEL = "API";
    private static final String ROUTE_PREFIX = "Sensitive route in JS: ";
    static final String TRY = "replay with another account's session and with none at all, then diff the data "
            + "returned (missing authz = IDOR / broken access control)";

    private AccessLeads() {
    }

    /**
     * @return the finding for this observation, or null when it isn't a lead: authed, non-2xx (or 204), a
     * preflight/HEAD, or neither an API (JSON/XML) response nor a sensitive route.
     */
    public static Finding lead(boolean authed, int status, String method, String path, String normalizedUrl,
                               String contentType, List<PatternRegistry.SecretRule> routeRules) {
        if (authed || status < 200 || status > 299 || status == 204) {
            return null;
        }
        String m = method == null ? "" : method.toUpperCase(Locale.ROOT);
        if (m.equals("OPTIONS") || m.equals("HEAD")) {
            return null;
        }
        String label = null;
        Finding.Severity severity = Finding.Severity.LOW;
        PatternRegistry.SecretRule rule = routeRules == null ? null : JsAnalyzer.routeRuleFor(path, routeRules);
        if (rule != null) {
            label = rule.name.startsWith(ROUTE_PREFIX) ? rule.name.substring(ROUTE_PREFIX.length()) : rule.name;
            severity = Finding.Severity.MEDIUM;
        } else if (isApi(contentType)) {
            label = API_LABEL;
        }
        if (label == null) {
            return null;
        }
        String evidence = "HTTP " + status + " to " + m + " sent without Authorization/Cookie  |  Try: " + TRY;
        return new Finding(TYPE_PREFIX + label, severity, m + " " + normalizedUrl, normalizedUrl, evidence, false);
    }

    static boolean isApi(String contentType) {
        if (contentType == null) {
            return false;
        }
        String ct = contentType.toLowerCase(Locale.ROOT);
        return ct.contains("json") || ct.contains("/xml") || ct.contains("+xml");
    }
}
