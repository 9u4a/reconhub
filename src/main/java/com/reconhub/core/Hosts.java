package com.reconhub.core;

import com.reconhub.model.Endpoint;

import java.net.URI;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

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

    /**
     * The scheme already observed for {@code host} in captured traffic ({@code "http"} or
     * {@code "https"}), or {@code "https"} if the host has no recorded endpoint yet. Prevents
     * defaulting to https against a host only ever seen over plain http (or vice versa) -- e.g. when
     * opening it in a browser or sending to Repeater. Delegates to {@link #schemesByHost} so the two
     * never drift apart. (Moved here from the removed {@code ui.RunBruteforceAction} in 0.46.0 -- it was
     * always a generic scheme helper, used by Dashboard/Tech/Settings, not bruteforce-specific.)
     */
    public static String inferScheme(DataStore store, String host) {
        if (store == null || host == null) {
            return "https";
        }
        return schemesByHost(store).getOrDefault(host.toLowerCase(Locale.ROOT), "https");
    }

    /**
     * The scheme observed for every host with at least one recorded endpoint, in a single pass over
     * {@link DataStore#snapshotEndpoints()} -- for callers needing this for many hosts at once (don't
     * call {@link #inferScheme} in a loop; that's an O(hosts &times; endpoints) trap). Keyed by
     * lower-cased host; first scheme encountered in {@code snapshotEndpoints()}'s deterministic order
     * wins when a host was seen under both.
     */
    public static Map<String, String> schemesByHost(DataStore store) {
        Map<String, String> schemes = new HashMap<>();
        if (store == null) {
            return schemes;
        }
        for (Endpoint e : store.snapshotEndpoints()) {
            String host = e.getHost();
            String url = e.getNormalizedUrl();
            if (host == null || url == null) {
                continue;
            }
            String scheme = url.startsWith("http://") ? "http"
                    : url.startsWith("https://") ? "https" : null;
            if (scheme != null) {
                schemes.putIfAbsent(host.toLowerCase(Locale.ROOT), scheme);
            }
        }
        return schemes;
    }
}
