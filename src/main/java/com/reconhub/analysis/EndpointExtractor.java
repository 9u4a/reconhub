package com.reconhub.analysis;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.URI;
import java.util.Set;
import java.util.TreeSet;

/**
 * Derives a normalized, deduplicable view of an endpoint from an {@link HttpRequest}.
 *
 * <p>Normalized URL = {@code scheme://host[:port]/path?name1&name2} — query <em>values</em> are
 * dropped but parameter <em>names</em> are kept (sorted), so {@code /search?q=a} and
 * {@code /search?q=b} collapse to one endpoint while {@code /search?q=} and {@code /search?page=}
 * stay distinct.
 */
public final class EndpointExtractor {

    public record EndpointInfo(String method, String host, String path,
                               String normalizedUrl, Set<String> paramNames) {}

    private EndpointExtractor() {}

    public static EndpointInfo extract(HttpRequest request) {
        String method = safe(request.method());
        String host = request.httpService() != null ? request.httpService().host() : "";
        String fullUrl = safe(request.url());

        String scheme = "http";
        int port = -1;
        String path = safe(request.pathWithoutQuery());
        try {
            URI uri = URI.create(fullUrl);
            if (uri.getScheme() != null) {
                scheme = uri.getScheme();
            }
            port = uri.getPort();
            if (uri.getPath() != null && !uri.getPath().isEmpty()) {
                path = uri.getPath();
            }
        } catch (RuntimeException ignored) {
            // Fall back to Montoya-provided pieces below.
        }

        Set<String> queryNames = new TreeSet<>();
        Set<String> allParamNames = new TreeSet<>();
        for (ParsedHttpParameter p : request.parameters()) {
            allParamNames.add(p.name());
            if (p.type() == HttpParameterType.URL) {
                queryNames.add(p.name());
            }
        }

        StringBuilder norm = new StringBuilder();
        norm.append(scheme).append("://").append(host);
        if (port > 0 && !isDefaultPort(scheme, port)) {
            norm.append(':').append(port);
        }
        norm.append(path);
        if (!queryNames.isEmpty()) {
            norm.append('?').append(String.join("&", queryNames));
        }

        return new EndpointInfo(method, host, path, norm.toString(), allParamNames);
    }

    private static boolean isDefaultPort(String scheme, int port) {
        return ("http".equalsIgnoreCase(scheme) && port == 80)
                || ("https".equalsIgnoreCase(scheme) && port == 443);
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }
}
