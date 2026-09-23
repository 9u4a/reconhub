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
    private final SecretScanner secretScanner;

    public MisconfigInspector(DataStore store, SecretScanner secretScanner) {
        this.store = store;
        this.secretScanner = secretScanner;
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
        checkCacheable(host, request, response, url);
    }

    /** Authenticated JSON responses without a private/no-store cache directive may be cached. */
    private void checkCacheable(String host, HttpRequest request, HttpResponse response, String url) {
        if (request == null || response.statusCode() != 200) {
            return;
        }
        boolean authed = request.headerValue("Authorization") != null
                || request.headerValue("Cookie") != null;
        String ct = response.headerValue("Content-Type");
        boolean json = ct != null && ct.toLowerCase(Locale.ROOT).contains("json");
        if (!authed || !json) {
            return;
        }
        String cc = response.headerValue("Cache-Control");
        String lower = cc == null ? "" : cc.toLowerCase(Locale.ROOT);
        boolean safe = lower.contains("no-store") || lower.contains("private")
                || lower.contains("no-cache");
        if (!safe) {
            add(Finding.Severity.LOW, "Sensitive response cacheable",
                    host + "|cache|" + url, url,
                    cc == null ? "no Cache-Control" : "Cache-Control: " + cc);
        }
    }

    private void checkCsp(String host, HttpResponse response, String url) {
        String csp = response.headerValue("Content-Security-Policy");
        if (csp == null || csp.isBlank()) {
            return;   // absence is already surfaced as a missing security header in the Tech tab
        }
        String lower = csp.toLowerCase(Locale.ROOT);
        boolean scriptCritical = lower.contains("script-src") || lower.contains("default-src");

        if (scriptCritical && lower.contains("'unsafe-inline'")) {
            add(Finding.Severity.MEDIUM, "CSP unsafe-inline",
                    host + "|csp|unsafe-inline", url, "unsafe-inline");
        }
        if (scriptCritical && lower.contains("'unsafe-eval'")) {
            add(Finding.Severity.MEDIUM, "CSP unsafe-eval",
                    host + "|csp|unsafe-eval", url, "unsafe-eval");
        }
        if (hasWildcardSource(lower)) {
            add(Finding.Severity.MEDIUM, "CSP wildcard src",
                    host + "|csp|wildcard", url, "wildcard src");
        }
        if (!lower.contains("frame-ancestors")) {
            add(Finding.Severity.LOW, "CSP no frame-ancestors",
                    host + "|csp|frame-ancestors", url, "no frame-ancestors");
        }
        if (!lower.contains("object-src") && !lower.contains("default-src")) {
            add(Finding.Severity.LOW, "CSP no object-src",
                    host + "|csp|object-src", url, "no object-src");
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

        String acaoTrim = acao.trim();
        if ("*".equals(acaoTrim) && credentials) {
            add(Finding.Severity.HIGH, "CORS wildcard +creds",
                    "acao=*|cred", url, "ACAO=* +creds");
        } else if (origin != null && origin.equalsIgnoreCase(acaoTrim) && credentials) {
            add(Finding.Severity.HIGH, "CORS reflected +creds",
                    "acao=reflected|" + acao, url, "ACAO reflects Origin +creds");
        } else if ("*".equals(acaoTrim)) {
            add(Finding.Severity.LOW, "CORS wildcard",
                    "acao=*", url, "ACAO=*");
        } else if (origin != null && origin.equalsIgnoreCase(acaoTrim)) {
            add(Finding.Severity.LOW, "CORS reflected",
                    "acao=reflected|" + acao, url, "ACAO reflects Origin");
        } else if (origin == null) {
            // ACAO present but the request that triggered it had no Origin header at all -- the server
            // is granting cross-origin access unconditionally, not just reflecting a browser-sent value.
            add(Finding.Severity.LOW, "CORS ACAO without Origin request",
                    "acao=no-origin|" + acao, url, "ACAO=" + acao + " but request had no Origin header");
        }

        // Wildcard on the allow-list headers is a separate (and separately dangerous) misconfiguration
        // from ACAO itself -- e.g. "*" here lets any preflight through regardless of ACAO's value.
        String acam = response.headerValue("Access-Control-Allow-Methods");
        if (acam != null && acam.contains("*")) {
            add(Finding.Severity.LOW, "CORS wildcard Allow-Methods",
                    "acam=*", url, "Access-Control-Allow-Methods: " + acam);
        }
        String acah = response.headerValue("Access-Control-Allow-Headers");
        if (acah != null && acah.contains("*")) {
            add(Finding.Severity.LOW, "CORS wildcard Allow-Headers",
                    "acah=*", url, "Access-Control-Allow-Headers: " + acah);
        }

        // A non-wildcard ACAO that reflects Origin without "Vary: Origin" risks a shared cache serving
        // one origin's CORS-enabled response to a different origin. Single-response check only (no
        // cross-request state), so this stays a simple presence check rather than a full poisoning proof.
        if (!"*".equals(acaoTrim) && origin != null && origin.equalsIgnoreCase(acaoTrim)) {
            String vary = response.headerValue("Vary");
            boolean variesOnOrigin = vary != null
                    && vary.toLowerCase(Locale.ROOT).contains("origin");
            if (!variesOnOrigin) {
                add(Finding.Severity.LOW, "CORS reflected without Vary: Origin",
                        "acao=novary|" + acao, url, "ACAO reflects Origin, no Vary: Origin");
            }
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
            // Cookie *values* aren't otherwise scanned anywhere (the secret scanner only ever sees
            // response bodies) -- a JWT or API key delivered purely via Set-Cookie was previously
            // invisible to the whole Findings/Secrets pipeline. Reuses the same scanner + rule set as
            // response bodies; a JWT match is picked up automatically by the existing JwtDecoder/
            // FindingsPanel JWT tab, no further wiring needed there.
            if (secretScanner != null) {
                secretScanner.scan(cookieValue(sc), url, currentMessages);
            }
            if (!lower.contains("httponly")) {
                add(Finding.Severity.LOW, "Cookie no HttpOnly",
                        host + "|" + name + "|httponly", url, name + ": no HttpOnly");
            }
            if (!lower.contains("secure")) {
                add(Finding.Severity.LOW, "Cookie no Secure",
                        host + "|" + name + "|secure", url, name + ": no Secure");
            }
            if (!lower.contains("samesite")) {
                add(Finding.Severity.INFO, "Cookie no SameSite",
                        host + "|" + name + "|samesite", url, name + ": no SameSite");
            }
        }
    }

    private static String cookieName(String setCookie) {
        int eq = setCookie.indexOf('=');
        String n = eq > 0 ? setCookie.substring(0, eq).trim() : setCookie.trim();
        return n.isEmpty() ? "(cookie)" : n;
    }

    /** The value portion of a Set-Cookie header: after the first '=', up to the first ';' (attrs). */
    private static String cookieValue(String setCookie) {
        int eq = setCookie.indexOf('=');
        if (eq < 0) {
            return "";
        }
        String rest = setCookie.substring(eq + 1);
        int semi = rest.indexOf(';');
        return (semi >= 0 ? rest.substring(0, semi) : rest).trim();
    }

    private void add(Finding.Severity sev, String type, String key, String url, String evidence) {
        Finding f = new Finding(type, sev, key, url, evidence, false);
        f.setMessages(currentMessages);
        store.recordFinding(f);
    }
}
