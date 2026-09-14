package com.reconhub.analysis;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.reconhub.core.DataStore;
import com.reconhub.model.TechInfo;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;

/**
 * Identifies server-side / client-side technology per host from response headers, cookies and body,
 * and records the checklist of missing security headers (computed on HTML documents only).
 */
public final class TechFingerprinter {

    private final DataStore store;
    private final PatternRegistry patterns;

    public TechFingerprinter(DataStore store, PatternRegistry patterns) {
        this.store = store;
        this.patterns = patterns;
    }

    public void fingerprint(String host, HttpResponse response, String contentType) {
        if (host == null || host.isBlank() || response == null) {
            return;
        }
        TechInfo ti = store.techForHost(host);

        String cookieJar = collectSetCookies(response);
        String body = null;   // lazily materialized only if a body rule needs it

        for (PatternRegistry.TechRule rule : patterns.techRules()) {
            switch (rule.source) {
                case "header" -> {
                    String value = response.headerValue(rule.header);
                    if (value != null) {
                        addIfMatch(ti, rule, value);
                    }
                }
                case "cookie" -> addIfMatch(ti, rule, cookieJar);
                case "body" -> {
                    if (isHtml(contentType)) {
                        if (body == null) {
                            body = response.bodyToString();
                        }
                        addIfMatch(ti, rule, body);
                    }
                }
                default -> { /* unknown source ignored */ }
            }
        }

        if (isHtml(contentType)) {
            ti.setMissingSecurityHeaders(missingSecurityHeaders(response));
        }
    }

    private void addIfMatch(TechInfo ti, PatternRegistry.TechRule rule, String text) {
        if (text == null || text.isEmpty()) {
            return;
        }
        Matcher m = rule.match.matcher(text);
        if (m.find()) {
            ti.addTechnology(substitute(rule.tech, m));
        }
    }

    /** Replaces {@code $1} in a tech label with capture group 1, when present. */
    private static String substitute(String tech, Matcher m) {
        if (tech != null && tech.contains("$1") && m.groupCount() >= 1 && m.group(1) != null) {
            return tech.replace("$1", m.group(1).trim());
        }
        return tech == null ? "" : tech.replace("$1", "").trim();
    }

    private static String collectSetCookies(HttpResponse response) {
        StringBuilder sb = new StringBuilder();
        for (HttpHeader h : response.headers()) {
            if ("Set-Cookie".equalsIgnoreCase(h.name())) {
                sb.append(h.value()).append('\n');
            }
        }
        return sb.toString();
    }

    private Set<String> missingSecurityHeaders(HttpResponse response) {
        Set<String> missing = new LinkedHashSet<>();
        for (String header : patterns.securityHeaders()) {
            if (response.headerValue(header) == null) {
                missing.add(header);
            }
        }
        return missing;
    }

    private static boolean isHtml(String contentType) {
        return contentType != null && contentType.toLowerCase().contains("html");
    }
}
