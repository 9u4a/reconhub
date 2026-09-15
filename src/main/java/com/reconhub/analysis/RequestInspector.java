package com.reconhub.analysis;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.reconhub.core.DataStore;
import com.reconhub.model.Finding;

import java.net.URI;
import java.util.Locale;

/**
 * Passive request-side checks that need the request parameters (and, when present, the response):
 * secrets/tokens carried in the URL, redirect parameters reflected into a {@code Location} header
 * (open-redirect candidate), and request parameter values reflected unencoded into an HTML response
 * (XSS test candidate). All findings are deduplicated; no traffic is generated.
 */
public final class RequestInspector {

    private static final int MAX_PER_RESPONSE = 20;

    private final DataStore store;

    public RequestInspector(DataStore store) {
        this.store = store;
    }

    public void inspect(HttpRequest request, HttpResponse response, String url,
                        String contentType, String body, HttpRequestResponse rr) {
        if (request == null) {
            return;
        }
        String host = hostOf(url);
        String path = pathOf(url);
        boolean html = contentType != null && contentType.toLowerCase(Locale.ROOT).contains("html");
        int status = response != null ? response.statusCode() : 0;
        String location = response != null ? response.headerValue("Location") : null;
        int emitted = 0;

        for (ParsedHttpParameter p : request.parameters()) {
            if (emitted >= MAX_PER_RESPONSE) {
                break;
            }
            HttpParameterType type = p.type();
            String name = p.name();
            String value = p.value();
            if (name == null) {
                continue;
            }

            // 1. Secret/token exposed in the URL query string.
            if (type == HttpParameterType.URL
                    && (isSensitiveName(name)
                        || (value != null && (JwtDecoder.isJwt(value) || highEntropy(value))))) {
                if (add(Finding.Severity.MEDIUM, "Secret in URL",
                        host + "|" + name, url, "'" + name + "' in URL", rr)) {
                    emitted++;
                }
                continue;
            }

            // 2. Open-redirect candidate: a redirect-class param value echoed into Location on a 3xx.
            if (status >= 300 && status < 400 && location != null && !location.isBlank()
                    && value != null && value.length() >= 4
                    && isRedirectName(name) && location.contains(value)) {
                if (add(Finding.Severity.MEDIUM, "Open redirect (candidate)",
                        host + "|" + path + "|" + name, url, "'" + name + "' → Location", rr)) {
                    emitted++;
                }
                continue;
            }

            // 3. Reflected parameter in an HTML response (manual-XSS test candidate).
            if (html && body != null && value != null && value.length() >= 6
                    && (type == HttpParameterType.URL || type == HttpParameterType.BODY)
                    && distinctive(value) && body.contains(value)) {
                if (add(Finding.Severity.INFO, "Reflected param (XSS?)",
                        host + "|" + path + "|" + name, url, "'" + name + "' reflected", rr)) {
                    emitted++;
                }
            }
        }
    }

    // ---- classification helpers -----------------------------------------

    private static boolean isSensitiveName(String name) {
        return ParameterClassifier.classify(name).contains("Secret/Token");
    }

    private static boolean isRedirectName(String name) {
        return ParameterClassifier.classify(name).contains("Redirect/SSRF");
    }

    /**
     * True for a longish, mixed-charset, high-entropy value — the kind of opaque token you don't
     * want travelling in a URL. Deliberately conservative to avoid flagging ordinary query values.
     */
    private static boolean highEntropy(String v) {
        if (v.length() < 20) {
            return false;
        }
        boolean hasLetter = false;
        boolean hasDigit = false;
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (Character.isLetter(c)) {
                hasLetter = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            }
        }
        return hasLetter && hasDigit && shannon(v) >= 3.5;
    }

    /** Shannon entropy in bits/char. */
    private static double shannon(String s) {
        int[] freq = new int[128];
        int counted = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 128) {
                freq[c]++;
                counted++;
            }
        }
        if (counted == 0) {
            return 0;
        }
        double h = 0;
        for (int f : freq) {
            if (f > 0) {
                double pr = (double) f / counted;
                h -= pr * (Math.log(pr) / Math.log(2));
            }
        }
        return h;
    }

    /**
     * A value distinctive enough that finding it verbatim in a response likely means the input was
     * echoed (rather than a coincidental common word): contains a markup-relevant special char, or
     * is a longer mixed string.
     */
    private static boolean distinctive(String v) {
        for (int i = 0; i < v.length(); i++) {
            if ("<>\"'();{}=".indexOf(v.charAt(i)) >= 0) {
                return true;
            }
        }
        return v.length() >= 10 && v.chars().anyMatch(c -> !Character.isLetter(c));
    }

    // ---- shared -----------------------------------------------------------

    private boolean add(Finding.Severity sev, String type, String key, String url, String evidence,
                        HttpRequestResponse rr) {
        Finding f = new Finding(type, sev, key, url, evidence, false);
        f.setMessages(rr);
        return store.recordFinding(f);
    }

    private static String hostOf(String url) {
        try {
            String h = URI.create(url).getHost();
            return h == null ? "" : h;
        } catch (RuntimeException e) {
            return "";
        }
    }

    private static String pathOf(String url) {
        try {
            String p = URI.create(url).getPath();
            return p == null ? "" : p;
        } catch (RuntimeException e) {
            return "";
        }
    }
}
