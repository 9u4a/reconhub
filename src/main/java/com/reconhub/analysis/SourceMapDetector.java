package com.reconhub.analysis;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.reconhub.core.DataStore;
import com.reconhub.model.Finding;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive detection of exposed JavaScript source maps — a bigger practical threat to minified/
 * obfuscated JS than the obfuscation itself, since a leaked map contains the full pre-bundle
 * original source (file paths, unminified code, often comments). Two independent signals, from
 * content that was already captured:
 *
 * <ul>
 *   <li><b>Reference</b> ({@link #checkJsBody}) — a JS body contains a {@code sourceMappingURL}
 *       comment. This is only a lead, not a confirmed leak: the map is <b>never fetched</b> here,
 *       so an external reference might 404. An inline {@code data:} URI is the one exception — the
 *       map bytes are already sitting right there in the body, so that case is a confirmed leak too.
 *   <li><b>Captured map</b> ({@link #analyze}) — a response ReconHub already saw <i>is</i> a source
 *       map. This is a confirmed leak: the map's {@code sources} array is the original,
 *       pre-minification file list. A {@code .map}-suffixed URL is not enough on its own to record
 *       this — the most common real case is a {@code sourceMappingURL} comment pointing at a map
 *       that 404s, which lands in traffic with a {@code .map} URL and an HTML error body. Recording
 *       on the suffix alone would report that as a confirmed leak of the opposite fact. The body is
 *       always parsed as JSON and must have a {@code sources} array and a {@code mappings} string
 *       before anything is recorded.
 * </ul>
 */
public final class SourceMapDetector {

    // //# or //@ (modern/legacy) and the /*# ... */ block form. The leading '/' of "//" or "/*" is
    // deliberately not matched (see the [/*"] before [#@]) -- find() only needs the character
    // immediately before the marker, which is sufficient discrimination since the required literal
    // "sourceMappingURL=" right after makes a false match on unrelated text (e.g. a "...#anchor"
    // URL fragment) essentially impossible.
    private static final Pattern SOURCE_MAP_COMMENT =
            Pattern.compile("[/*][#@]\\s*sourceMappingURL\\s*=\\s*([^\\s'\"*]+)");

    private static final int MAX_PARSE = 8_000_000;    // parse sources[] up to this size
    private static final int MAX_SNIFF = 20_000_000;   // don't even attempt above this
    private static final int MAX_EVIDENCE = 300;
    private static final int SAMPLE_SOURCES = 3;

    private final DataStore store;

    public SourceMapDetector(DataStore store) {
        this.store = store;
    }

    // ---- Case A: a JS body references a source map -----------------------

    /** Scans an already-analyzed JS body for a {@code sourceMappingURL} comment. Never fetches it. */
    public void checkJsBody(String jsUrl, String body, HttpRequestResponse rr) {
        if (body == null || body.indexOf("sourceMappingURL") < 0) {
            return;   // cheap bail-out before the regex touches a possibly multi-MB bundle
        }
        Matcher m = SOURCE_MAP_COMMENT.matcher(body);
        if (!m.find()) {
            return;
        }
        String ref = m.group(1).trim();
        if (ref.isEmpty()) {
            return;
        }
        if (ref.toLowerCase(Locale.ROOT).startsWith("data:")) {
            record(new Finding("Inline source map exposed", Finding.Severity.MEDIUM,
                    "sourcemap-inline|" + jsUrl, jsUrl,
                    trunc("embedded " + dataPrefix(ref) + ", " + ref.length() + " chars in body"),
                    false), rr);
            return;
        }
        String resolved = resolve(jsUrl, ref);
        record(new Finding("Source map reference exposed", Finding.Severity.LOW,
                "sourcemap-ref|" + resolved, jsUrl,
                trunc("sourceMappingURL=" + ref + " → " + resolved + " (not fetched)"), false), rr);
    }

    // ---- Case B: a response IS an already-captured source map ------------

    /** Checks whether an already-captured response is itself a source map. Never sends a request. */
    public void analyze(String url, String contentType, String body, HttpRequestResponse rr) {
        if (body == null || body.isEmpty() || body.length() > MAX_SNIFF) {
            return;
        }
        if (!isMapUrl(url) && !looksLikeMapJson(body)) {
            return;
        }
        // Confirm by parsing -- a .map URL alone is not enough (see class javadoc: the 404 trap).
        if (body.length() > MAX_PARSE) {
            // Too large to safely enumerate sources, but the suffix/sniff pre-check already makes
            // this a strong signal on its own -- record it rather than silently drop the biggest,
            // most valuable leaks.
            if (looksLikeMapJson(body)) {
                record(new Finding("Source map exposed", Finding.Severity.MEDIUM,
                        "sourcemap|" + url, url,
                        trunc("valid source map, " + body.length()
                                + " chars (too large to enumerate sources)"), false), rr);
            }
            return;
        }
        try {
            JsonElement root = JsonParser.parseString(body);
            if (!root.isJsonObject()) {
                return;
            }
            JsonObject obj = root.getAsJsonObject();
            JsonElement sourcesEl = obj.get("sources");
            JsonElement mappingsEl = obj.get("mappings");
            if (sourcesEl == null || !sourcesEl.isJsonArray()
                    || mappingsEl == null || !mappingsEl.isJsonPrimitive()
                    || !mappingsEl.getAsJsonPrimitive().isString()) {
                return;
            }
            JsonArray sources = sourcesEl.getAsJsonArray();
            List<String> sample = new ArrayList<>();
            for (int i = 0; i < sources.size() && sample.size() < SAMPLE_SOURCES; i++) {
                JsonElement e = sources.get(i);
                if (e.isJsonPrimitive() && e.getAsJsonPrimitive().isString()) {
                    sample.add(e.getAsString());
                }
            }
            record(new Finding("Source map exposed", Finding.Severity.MEDIUM,
                    "sourcemap|" + url, url,
                    trunc(sources.size() + " original sources: " + String.join(", ", sample)), false), rr);
        } catch (RuntimeException ignored) {
            // not actually valid JSON / not really a source map (e.g. a 404 HTML page at a .map URL)
        }
    }

    // ---- helpers -----------------------------------------------------------

    private static boolean isMapUrl(String url) {
        if (url == null) {
            return false;
        }
        String u = url.toLowerCase(Locale.ROOT);
        int q = u.indexOf('?');
        if (q >= 0) {
            u = u.substring(0, q);
        }
        int h = u.indexOf('#');
        if (h >= 0) {
            u = u.substring(0, h);
        }
        return u.endsWith(".map");
    }

    /** Cheap pre-check only -- never the sole basis for recording a finding (see {@link #analyze}). */
    private static boolean looksLikeMapJson(String body) {
        String trimmed = body.stripLeading();
        return trimmed.startsWith("{") && trimmed.contains("\"version\"")
                && trimmed.contains("\"sources\"") && trimmed.contains("\"mappings\"");
    }

    private static String dataPrefix(String ref) {
        int comma = ref.indexOf(',');
        String prefix = comma >= 0 ? ref.substring(0, comma + 1) : ref;
        return prefix.length() > 60 ? prefix.substring(0, 60) + "…" : prefix;
    }

    /** Resolves a (possibly relative) source-map reference against the JS file's own URL. Falls back
     * to the raw reference when the base/ref can't be parsed as a URI (e.g. a synthetic
     * {@code import://} URL from a manually-imported local JS file). */
    private static String resolve(String baseUrl, String ref) {
        try {
            return URI.create(baseUrl).resolve(ref).toString();
        } catch (RuntimeException e) {
            return ref;
        }
    }

    private static String trunc(String s) {
        if (s == null) {
            return "";
        }
        return s.length() > MAX_EVIDENCE ? s.substring(0, MAX_EVIDENCE) + "…" : s;
    }

    private void record(Finding f, HttpRequestResponse rr) {
        f.setMessages(rr);
        store.recordFinding(f);
    }
}
