package com.reconhub.core;

import java.net.URI;

/**
 * URL to host extraction/display-label helpers. Replaces 7 near-identical private {@code hostOf}/
 * {@code hostLabel} copies that had accumulated across {@code DataStore}, {@code JsAnalyzer}, {@code
 * RequestInspector}, {@code HtmlReporter}, {@code MarkdownReporter}, {@code DashboardPanel} and {@code
 * FindingsPanel}. Six of those seven were byte-for-byte equivalent; {@code FindingsPanel}'s copy also
 * rejected any URL not starting with {@code "http"} before attempting to parse it, but a {@code Finding}'s
 * {@code locationUrl} only ever comes from captured HTTP traffic or JS analysis, so that extra guard could
 * never actually reject anything a plain {@code URI.create} + null-host check wouldn't already turn into
 * {@code ""} -- consolidating onto this class is behavior-preserving.
 */
public final class Hosts {

    private Hosts() {}

    /** The host of an absolute URL. Null, blank, relative, or unparseable input all yield {@code ""}. */
    public static String of(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }
        try {
            String h = URI.create(url).getHost();
            return h == null ? "" : h;
        } catch (RuntimeException e) {
            return "";
        }
    }

    /** Display label for a host string -- rows with no host (relative paths, JS-internal references)
     * show as {@code "(relative / JS)"} instead of an empty cell. */
    public static String label(String host) {
        return host == null || host.isBlank() ? "(relative / JS)" : host;
    }

    /** Shorthand for {@code label(of(url))}. */
    public static String labelOf(String url) {
        return label(of(url));
    }
}
