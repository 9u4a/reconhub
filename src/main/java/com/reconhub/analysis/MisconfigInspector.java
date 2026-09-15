package com.reconhub.analysis;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.reconhub.core.DataStore;
import com.reconhub.model.Finding;

import java.util.Locale;

/**
 * Passive security-misconfiguration checks on a response: permissive CORS and missing cookie
 * security flags. Emits {@link Finding}s (deduplicated by type + a stable key).
 */
public final class MisconfigInspector {

    private final DataStore store;

    public MisconfigInspector(DataStore store) {
        this.store = store;
    }

    private HttpRequestResponse currentMessages;   // set per inspect() (single ingest thread)

    public void inspect(String host, HttpRequest request, HttpResponse response, String url) {
        if (response == null) {
            return;
        }
        this.currentMessages = request != null
                ? HttpRequestResponse.httpRequestResponse(request, response) : null;
        checkCors(request, response, url);
        checkCookies(host, response, url);
        checkCsp(host, response, url);
    }

    private void checkCsp(String host, HttpResponse response, String url) {
        String csp = response.headerValue("Content-Security-Policy");
        if (csp == null || csp.isBlank()) {
            return;   // absence is already surfaced as a missing security header in the Tech tab
        }
        String lower = csp.toLowerCase(Locale.ROOT);
        boolean scriptCritical = lower.contains("script-src") || lower.contains("default-src");

        if (scriptCritical && lower.contains("'unsafe-inline'")) {
            add(Finding.Severity.MEDIUM, "CSP allows 'unsafe-inline'",
                    host + "|csp|unsafe-inline", url,
                    "Content-Security-Policy permits 'unsafe-inline' (weakens XSS protection)");
        }
        if (scriptCritical && lower.contains("'unsafe-eval'")) {
            add(Finding.Severity.MEDIUM, "CSP allows 'unsafe-eval'",
                    host + "|csp|unsafe-eval", url,
                    "Content-Security-Policy permits 'unsafe-eval'");
        }
        if (hasWildcardSource(lower)) {
            add(Finding.Severity.MEDIUM, "CSP wildcard source",
                    host + "|csp|wildcard", url,
                    "Content-Security-Policy uses a wildcard (*) source in script-src/default-src");
        }
        if (!lower.contains("frame-ancestors")) {
            add(Finding.Severity.LOW, "CSP missing frame-ancestors",
                    host + "|csp|frame-ancestors", url,
                    "Content-Security-Policy has no frame-ancestors (clickjacking not restricted by CSP)");
        }
        if (!lower.contains("object-src") && !lower.contains("default-src")) {
            add(Finding.Severity.LOW, "CSP missing object-src",
                    host + "|csp|object-src", url,
                    "Content-Security-Policy has neither object-src nor default-src");
        }
    }

    /** True when script-src or default-src lists a bare "*" source. */
    private static boolean hasWildcardSource(String cspLower) {
        for (String directive : cspLower.split(";")) {
            String d = directive.trim();
            if (d.startsWith("script-src") || d.startsWith("default-src")) {
                for (String tok : d.split("\\s+")) {
                    if (tok.equals("*")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private void checkCors(HttpRequest request, HttpResponse response, String url) {
        String acao = response.headerValue("Access-Control-Allow-Origin");
        if (acao == null) {
            return;
        }
        String acac = response.headerValue("Access-Control-Allow-Credentials");
        boolean credentials = "true".equalsIgnoreCase(acac);
        String origin = request != null ? request.headerValue("Origin") : null;

        if ("*".equals(acao.trim()) && credentials) {
            add(Finding.Severity.HIGH, "CORS: wildcard origin with credentials",
                    "acao=*|cred", url, "Access-Control-Allow-Origin: * with Allow-Credentials: true");
        } else if (origin != null && origin.equalsIgnoreCase(acao.trim()) && credentials) {
            add(Finding.Severity.HIGH, "CORS: reflected origin with credentials",
                    "acao=reflected|" + acao, url,
                    "ACAO reflects request Origin (" + acao + ") with Allow-Credentials: true");
        } else if ("*".equals(acao.trim())) {
            add(Finding.Severity.LOW, "CORS: wildcard origin",
                    "acao=*", url, "Access-Control-Allow-Origin: *");
        } else if (origin != null && origin.equalsIgnoreCase(acao.trim())) {
            add(Finding.Severity.LOW, "CORS: reflected origin",
                    "acao=reflected|" + acao, url, "ACAO reflects request Origin: " + acao);
        }
    }

    private void checkCookies(String host, HttpResponse response, String url) {
        for (HttpHeader h : response.headers()) {
            if (!"Set-Cookie".equalsIgnoreCase(h.name())) {
                continue;
            }
            String sc = h.value();
            String name = cookieName(sc);
            String lower = sc.toLowerCase(Locale.ROOT);
            if (!lower.contains("httponly")) {
                add(Finding.Severity.LOW, "Cookie without HttpOnly",
                        host + "|" + name + "|httponly", url, "Set-Cookie " + name + " missing HttpOnly");
            }
            if (!lower.contains("secure")) {
                add(Finding.Severity.LOW, "Cookie without Secure",
                        host + "|" + name + "|secure", url, "Set-Cookie " + name + " missing Secure");
            }
            if (!lower.contains("samesite")) {
                add(Finding.Severity.INFO, "Cookie without SameSite",
                        host + "|" + name + "|samesite", url, "Set-Cookie " + name + " missing SameSite");
            }
        }
    }

    private static String cookieName(String setCookie) {
        int eq = setCookie.indexOf('=');
        String n = eq > 0 ? setCookie.substring(0, eq).trim() : setCookie.trim();
        return n.isEmpty() ? "(cookie)" : n;
    }

    private void add(Finding.Severity sev, String type, String key, String url, String evidence) {
        Finding f = new Finding(type, sev, key, url, evidence, false);
        f.setMessages(currentMessages);
        store.recordFinding(f);
    }
}
