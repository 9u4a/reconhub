package com.reconhub.analysis;

import com.reconhub.model.Finding;

import java.util.Collection;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive request-shape leads (0.57.0): CSRF candidates, file-upload endpoints and auth-flow endpoints
 * (login / OTP / password reset / signup / token refresh), driven by {@code patterns/leads.json}. Each
 * returns a finding or null; one finding per method + normalized URL. Pure/static for headless testing --
 * the caller passes in what it already parsed from the request. Never sends anything.
 */
public final class RequestLeads {

    public static final String CSRF_TYPE = "CSRF candidate";
    public static final String UPLOAD_TYPE = "File upload endpoint";
    public static final String AUTH_FLOW_PREFIX = "Auth flow endpoint: ";

    static final String CSRF_TRY_SIMPLE = "rebuild it as an auto-submitting HTML form on another origin (Burp "
            + "Engagement tools > Generate CSRF PoC) and submit it with the victim's session";
    static final String CSRF_TRY_JSON = "resend the body as text/plain or form-urlencoded -- if the server "
            + "still accepts it, a cross-site form can forge it; also check the session cookie's SameSite";
    static final String UPLOAD_TRY = "upload with a double / mixed-case / null-byte extension, a spoofed "
            + "Content-Type and magic bytes, then find where the file is served (web shell, SVG/HTML -> stored "
            + "XSS, path traversal in the filename)";

    // A file part in a multipart body; group 1 = filename. Self-limiting classes, bounded spans.
    static final Pattern FILE_PART = Pattern.compile(
            "(?i)content-disposition:[^\\r\\n]{0,300}?filename\\*?=\\s*\"?([^\"\\r\\n;]{0,200})");
    private static final int MAX_BODY_HEAD = 64 * 1024;

    private RequestLeads() {
    }

    /**
     * A cookie-authenticated POST with no anti-CSRF token parameter and no anti-CSRF / custom header. LOW
     * when the body type is one a cross-site form can send (form, multipart, text/plain, none), INFO for
     * JSON (needs a content-type downgrade). Requests with an Authorization header are skipped (browsers
     * don't attach it cross-site), as are login/signup posts (login CSRF is rarely worth a report).
     *
     * @param paramNames request parameter names excluding cookies
     */
    public static Finding csrf(String method, String path, String normalizedUrl, int status, boolean hasCookie,
                               boolean hasAuthorization, Collection<String> headerNames,
                               Collection<String> paramNames, String requestContentType,
                               PatternRegistry.LeadRules rules) {
        if (rules == null || !"POST".equalsIgnoreCase(method) || !hasCookie || hasAuthorization
                || status < 200 || status >= 400) {
            return null;
        }
        if (headerNames != null) {
            for (String h : headerNames) {
                if (PatternRegistry.LeadRules.whole(rules.csrfHeaders, h)) {
                    return null;
                }
            }
        }
        if (paramNames != null) {
            for (String p : paramNames) {
                if (PatternRegistry.LeadRules.whole(rules.csrfTokenNames, p)) {
                    return null;
                }
            }
        }
        PatternRegistry.SecretRule flow = authFlowRule(path, rules);
        if (flow != null && (flow.name.equals("login") || flow.name.equals("signup"))) {
            return null;
        }
        String ct = requestContentType == null ? "" : requestContentType.toLowerCase(Locale.ROOT);
        boolean json = ct.contains("json");
        boolean simple = ct.isBlank() || ct.contains("x-www-form-urlencoded") || ct.contains("multipart/form-data")
                || ct.startsWith("text/plain");
        if (!json && !simple) {
            return null;
        }
        String kind = json ? "JSON" : ct.isBlank() ? "no body type" : ct.split(";", 2)[0].trim();
        String evidence = "Cookie-authenticated POST (" + kind + ") with no anti-CSRF token or header  |  Try: "
                + (json ? CSRF_TRY_JSON : CSRF_TRY_SIMPLE);
        return new Finding(CSRF_TYPE, json ? Finding.Severity.INFO : Finding.Severity.LOW,
                "POST " + normalizedUrl, normalizedUrl, evidence, false);
    }

    /** A multipart request that carries a file part. {@code bodyHead} may be the whole body; only the first
     * 64K chars are looked at. */
    public static Finding upload(String method, String normalizedUrl, String requestContentType, String bodyHead) {
        if (requestContentType == null || bodyHead == null
                || !requestContentType.toLowerCase(Locale.ROOT).contains("multipart/")) {
            return null;
        }
        String head = bodyHead.length() > MAX_BODY_HEAD ? bodyHead.substring(0, MAX_BODY_HEAD) : bodyHead;
        Matcher m = FILE_PART.matcher(head);
        if (!m.find()) {
            return null;
        }
        String m0 = method == null ? "POST" : method.toUpperCase(Locale.ROOT);
        String file = m.group(1).trim();
        String evidence = "multipart file part" + (file.isEmpty() ? "" : " (filename \"" + file + "\")")
                + "  |  Try: " + UPLOAD_TRY;
        return new Finding(UPLOAD_TYPE, Finding.Severity.INFO, m0 + " " + normalizedUrl, normalizedUrl, evidence,
                false);
    }

    /** A POST/PUT to a path in one of the leads.json auth-flow families; notes when the response carried no
     * rate-limit header (a hint, not proof -- limits are often enforced without one). */
    public static Finding authFlow(String method, String path, String normalizedUrl, int status,
                                   Collection<String> responseHeaderNames, PatternRegistry.LeadRules rules) {
        String m = method == null ? "" : method.toUpperCase(Locale.ROOT);
        if (rules == null || !(m.equals("POST") || m.equals("PUT")) || status == 0) {
            return null;
        }
        PatternRegistry.SecretRule rule = authFlowRule(path, rules);
        if (rule == null) {
            return null;
        }
        boolean limited = false;
        if (responseHeaderNames != null) {
            for (String h : responseHeaderNames) {
                if (PatternRegistry.LeadRules.whole(rules.rateLimitHeaders, h)) {
                    limited = true;
                    break;
                }
            }
        }
        String evidence = m + " to a " + rule.name + " endpoint (HTTP " + status + ")"
                + (limited ? "" : ", no rate-limit header in the response")
                + (rule.note == null ? "" : "  |  Try: " + rule.note);
        return new Finding(AUTH_FLOW_PREFIX + rule.name, Finding.Severity.INFO, m + " " + normalizedUrl,
                normalizedUrl, evidence, false);
    }

    static PatternRegistry.SecretRule authFlowRule(String path, PatternRegistry.LeadRules rules) {
        if (path == null || path.isEmpty() || rules == null) {
            return null;
        }
        for (PatternRegistry.SecretRule r : rules.authFlows) {
            if (r.pattern.matcher(path).find()) {
                return r;
            }
        }
        return null;
    }
}
