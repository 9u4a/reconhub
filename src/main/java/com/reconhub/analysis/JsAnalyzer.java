package com.reconhub.analysis;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.core.DataStore;
import com.reconhub.core.HashUtil;
import com.reconhub.core.Hosts;
import com.reconhub.core.Settings;
import com.reconhub.export.JsFileWriter;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Collects a JavaScript body: dedups by SHA-256, optionally writes it to disk, and mines it for
 * endpoints (LinkFinder-style) and secrets (reusing {@link SecretScanner}).
 */
public final class JsAnalyzer {

    private static final int MAX_LINKS_PER_RULE = 500;
    private static final int PREVIEW_MAX = 160;
    private static final int PREVIEW_SAMPLES = 3;
    // 0.43.7: isInterestingLink used to call link.toLowerCase() (an allocation) + Pattern.compile(...)
    // (a fresh compile) on every candidate link -- up to MAX_LINKS_PER_RULE x jsLinkRules().size()
    // (2000 at current rule counts) per JS bundle. Hoisted to a static final, case-insensitive Pattern
    // so it's compiled once and needs no lowercased copy of the input.
    private static final Pattern MIME_LIKE =
            Pattern.compile("[a-z]+/[a-z0-9.+-]+", Pattern.CASE_INSENSITIVE);
    /** Cap on sensitive-route findings from one body (0.55.0) -- one bundle can't flood the tab. */
    private static final int MAX_ROUTES_PER_BODY = 30;
    // Hidden-parameter caps (0.56.0): names collected per body, and how many become findings.
    static final int MAX_PARAMS_PER_BODY = 200;
    private static final int MAX_PARAM_FINDINGS_PER_BODY = 30;
    public static final String HIDDEN_PARAM_PREFIX = "Hidden parameter in JS: ";
    /** A link ending in one of these is a static asset, never a "sensitive route". */
    private static final Set<String> STATIC_EXT = Set.of("css", "png", "jpg", "jpeg", "gif", "svg", "ico",
            "webp", "avif", "bmp", "woff", "woff2", "ttf", "otf", "eot", "map", "mp3", "mp4", "webm", "ogg",
            "wav", "pdf", "txt", "js", "mjs", "ts", "tsx", "jsx", "scss", "less");

    private final MontoyaApi api;   // nullable (headless tests); used only to log a save failure
    private final DataStore store;
    private final PatternRegistry patterns;
    private final SecretScanner secretScanner;
    private final SecretScanner jsFindingScanner;   // crypto/authz/config/api-auth locators (0.47.0)
    private final JsFlowAnalyzer flowAnalyzer;       // actionable source→sink flow findings (0.52.0)
    private final JsPairAnalyzer pairAnalyzer;        // actionable anchor→target pairings (0.53.0)
    private final CommentExtractor commentExtractor;
    private final SourceMapDetector sourceMapDetector;
    private final Settings settings;
    private final AtomicInteger saveFailures = new AtomicInteger();

    public JsAnalyzer(MontoyaApi api, DataStore store, PatternRegistry patterns,
                      SecretScanner secretScanner, SecretScanner jsFindingScanner,
                      JsFlowAnalyzer flowAnalyzer, JsPairAnalyzer pairAnalyzer,
                      CommentExtractor commentExtractor,
                      SourceMapDetector sourceMapDetector, Settings settings) {
        this.api = api;
        this.store = store;
        this.patterns = patterns;
        this.secretScanner = secretScanner;
        this.jsFindingScanner = jsFindingScanner;
        this.flowAnalyzer = flowAnalyzer;
        this.pairAnalyzer = pairAnalyzer;
        this.commentExtractor = commentExtractor;
        this.sourceMapDetector = sourceMapDetector;
        this.settings = settings;
    }

    public void analyze(String url, String body, HttpRequestResponse messages) {
        if (body == null || body.isBlank()) {
            return;
        }
        String sha = HashUtil.sha256(body);
        if (store.hasJsAsset(sha)) {
            return;   // identical bundle already processed
        }

        JsAsset asset = store.recordJsAsset(new JsAsset(url, sha, body.length()));
        asset.setMessages(messages);   // null for a manually-imported local file -- that's correct
        // Library / vendor / third-party code (0.55.0): still stored, saved, secret-scanned and
        // source-map-checked, but skips endpoint extraction + every deep-analysis pass unless the user
        // opted in -- those passes are where library code turned into noise (and the biggest CPU cost).
        asset.setKind(JsLibraryClassifier.shared().classify(url, body));
        boolean deep = !asset.isLibrary() || settings.isAnalyzeLibraryJs();

        if (settings.isSaveJsToDisk()) {
            try {
                asset.setSavedPath(
                        JsFileWriter.write(settings.getJsSaveDirectory(), url, sha, body).toString());
            } catch (IOException | RuntimeException e) {
                logSaveFailure(e);
            }
        }

        List<String> links = deep ? extractEndpoints(url, body, messages) : List.of();
        asset.setExtractedEndpoints(links.size());
        asset.setPreview(buildPreview(links, body));

        int secrets = secretScanner.scan(body, url, messages);
        asset.setExtractedSecrets(secrets);

        sourceMapDetector.checkJsBody(url, body, messages);
        if (!deep) {
            return;
        }

        // Deep JS analysis (0.47.0): crypto/authz/sink/config locators. Runs here (not only in
        // TrafficIngestor.process) so a manually-imported JS file is analyzed too. Findings only --
        // not counted into the "Secrets" column.
        if (jsFindingScanner != null) {
            jsFindingScanner.scan(body, url, messages);
        }
        recordHiddenParams(url, body, messages);
        // Actionable DOM-XSS-style flow findings (source→sink proximity + how-to-test hint, 0.52.0).
        if (flowAnalyzer != null) {
            flowAnalyzer.analyze(body, url, messages);
        }
        // Actionable anchor→target pairings (gated route, embedded key, 0.53.0).
        if (pairAnalyzer != null) {
            pairAnalyzer.analyze(body, url, messages);
        }

        if (settings.isRunPassiveChecks()) {
            commentExtractor.extractJs(body, url, messages);
        }
    }

    /** Logs a "Save JS to disk" failure, rate-limited: an unwritable directory fails for *every* JS
     * body, so logging each one would flood Burp's error log. */
    private void logSaveFailure(Exception e) {
        int n = saveFailures.incrementAndGet();
        if (api == null || (n > 3 && n % 100 != 0)) {
            return;
        }
        api.logging().logToError("ReconHub: saving JS to " + settings.getJsSaveDirectory()
                + " failed (failure #" + n + "; check Settings → JavaScript collection): " + e);
    }

    /** @return the distinct links discovered (insertion order), so the caller can both count them and
     * sample a few for {@link #buildPreview}. */
    private List<String> extractEndpoints(String jsUrl, String body, HttpRequestResponse messages) {
        String host = Hosts.of(jsUrl);
        // LinkedHashSet, not HashSet: preview sampling needs a deterministic order (the same body is
        // only ever analyzed once, due to SHA-256 dedup, so its preview must come out the same way
        // every time -- not depend on HashSet's unspecified iteration order).
        Set<String> seen = new LinkedHashSet<>();
        for (PatternRegistry.JsLinkRule rule : patterns.jsLinkRules()) {
            Matcher m = rule.pattern.matcher(body);
            int hits = 0;
            while (m.find() && hits < MAX_LINKS_PER_RULE) {
                hits++;
                String link = m.groupCount() >= 1 && m.group(1) != null ? m.group(1) : m.group();
                link = link.trim();
                if (!isInterestingLink(link) || !seen.add(link)) {
                    continue;
                }
                String linkHost = link.startsWith("http") ? Hosts.of(link) : host;
                store.recordEndpoint("JS", linkHost, link, link, 0, "", "js",
                        Set.of(), null, Set.of(jsUrl));
            }
        }
        recordSensitiveRoutes(seen, jsUrl, messages);
        return new ArrayList<>(seen);
    }

    /** One finding per (route rule, route) for links that look like sensitive surface (0.55.0) -- the
     * how-to-test note rides in the evidence, like every other actionable JS finding. */
    private void recordSensitiveRoutes(Set<String> links, String jsUrl, HttpRequestResponse messages) {
        List<PatternRegistry.SecretRule> rules = patterns.jsRouteRules();
        if (rules.isEmpty()) {
            return;
        }
        int recorded = 0;
        for (String link : links) {
            if (recorded >= MAX_ROUTES_PER_BODY) {
                break;
            }
            PatternRegistry.SecretRule rule = routeRuleFor(link, rules);
            if (rule == null) {
                continue;
            }
            String evidence = "route referenced in JS" + (rule.note == null ? "" : "  |  Try: " + rule.note);
            Finding f = new Finding(rule.name, rule.severity, link, jsUrl, evidence, false);
            f.setMessages(messages);
            store.recordFinding(f);
            recorded++;
        }
    }

    /** Hidden parameters (0.56.0): every name goes to the wordlist; names matching the "interesting" list
     * become one finding each (deduped by name across bundles) with a how-to-test hint. */
    private void recordHiddenParams(String jsUrl, String body, HttpRequestResponse messages) {
        if (patterns.jsParamRules().isEmpty()) {
            return;
        }
        Pattern interesting = patterns.jsParamInteresting();
        int recorded = 0;
        for (String name : paramNames(body, patterns.jsParamRules())) {
            store.recordJsParamName(name, jsUrl);
            if (recorded >= MAX_PARAM_FINDINGS_PER_BODY || !isInterestingParam(name, interesting)) {
                continue;
            }
            Finding f = new Finding(HIDDEN_PARAM_PREFIX + name, Finding.Severity.LOW, name, jsUrl,
                    "parameter referenced in JS  |  Try: add ?" + name + "=1 (or true / admin / another "
                            + "user's id) to the endpoints that use it and diff the response", false);
            f.setMessages(messages);
            store.recordFinding(f);
            recorded++;
        }
    }

    /** Distinct parameter names (group 1) the rules find in {@code body}, insertion order, capped at
     * {@link #MAX_PARAMS_PER_BODY}. Pure/static for headless testing. */
    static Set<String> paramNames(String body, List<PatternRegistry.JsLinkRule> rules) {
        Set<String> names = new LinkedHashSet<>();
        for (PatternRegistry.JsLinkRule rule : rules) {
            Matcher m = rule.pattern.matcher(body);
            while (names.size() < MAX_PARAMS_PER_BODY && m.find()) {
                String n = m.groupCount() >= 1 ? m.group(1) : null;
                if (n != null && n.length() >= 2) {
                    names.add(n);
                }
            }
        }
        return names;
    }

    static boolean isInterestingParam(String name, Pattern interesting) {
        return interesting != null && interesting.matcher(name).find();
    }

    /** The first route rule matching {@code link}'s path, or null (static assets never match). Pure/
     * static for headless testing. */
    public static PatternRegistry.SecretRule routeRuleFor(String link, List<PatternRegistry.SecretRule> rules) {
        String path = routePath(link);
        if (path.isEmpty() || isStaticAsset(path)) {
            return null;
        }
        for (PatternRegistry.SecretRule r : rules) {
            if (r.pattern.matcher(path).find()) {
                return r;
            }
        }
        return null;
    }

    /** {@code link}'s path for route matching / "seen in traffic" lookup: scheme+host and fragment
     * dropped, query kept off, leading '/' ensured, trailing '/' trimmed. Public so the JS Analysis
     * tab's Seen column normalizes captured endpoint paths the same way. */
    public static String routePath(String link) {
        if (link == null) {
            return "";
        }
        String p = link.trim();
        int scheme = p.indexOf("://");
        if (scheme >= 0) {
            int slash = p.indexOf('/', scheme + 3);
            p = slash < 0 ? "/" : p.substring(slash);
        } else if (p.startsWith("//")) {
            int slash = p.indexOf('/', 2);
            p = slash < 0 ? "/" : p.substring(slash);
        }
        int cut = p.length();
        int q = p.indexOf('?');
        if (q >= 0) cut = Math.min(cut, q);
        int h = p.indexOf('#');
        if (h >= 0) cut = Math.min(cut, h);
        p = p.substring(0, cut);
        if (p.startsWith("./")) {
            p = p.substring(1);
        }
        if (!p.startsWith("/")) {
            p = "/" + p;
        }
        while (p.length() > 1 && p.endsWith("/")) {
            p = p.substring(0, p.length() - 1);
        }
        return p;
    }

    private static boolean isStaticAsset(String path) {
        int slash = path.lastIndexOf('/');
        int dot = path.lastIndexOf('.');
        return dot > slash && STATIC_EXT.contains(path.substring(dot + 1).toLowerCase(Locale.ROOT));
    }

    /**
     * A short, identifying hint for a JS asset that's more useful than a code snippet at telling
     * hash-named code-split chunks apart: a webpack/Vite chunk's first ~100 characters are near-
     * identical boilerplate across every chunk, but "talks to /api/admin/users" instantly identifies
     * one. Falls back to a code snippet only when no links were found in this body.
     */
    static String buildPreview(List<String> links, String body) {
        List<String> samples = pickSamples(links, PREVIEW_SAMPLES);
        if (samples.isEmpty()) {
            return JsBeautifier.snippet(body, PREVIEW_MAX);
        }
        String joined = String.join(", ", samples);
        return joined.length() > PREVIEW_MAX ? joined.substring(0, PREVIEW_MAX) + "…" : joined;
    }

    /** Prioritizes API-ish paths, then any absolute path, then everything else. */
    private static List<String> pickSamples(List<String> links, int max) {
        List<String> out = new ArrayList<>(max);
        for (String l : links) {
            if (out.size() >= max) break;
            if (l.contains("/api")) out.add(l);
        }
        for (String l : links) {
            if (out.size() >= max) break;
            if (!out.contains(l) && l.startsWith("/")) out.add(l);
        }
        for (String l : links) {
            if (out.size() >= max) break;
            if (!out.contains(l)) out.add(l);
        }
        return out;
    }

    private static boolean isInterestingLink(String link) {
        if (link.length() < 3 || link.length() > 300) {
            return false;
        }
        // Cheap checks first (0.43.7) -- template placeholders are plain contains() scans, tried before
        // the regex below so most non-interesting candidates never reach it.
        if (link.contains("${") || link.contains("{{") || link.contains("<%")) {
            return false;
        }
        // Drop obvious noise: mime types, pure file extensions ("text/html", "image/png").
        if (MIME_LIKE.matcher(link).matches()) {
            return false;
        }
        return link.startsWith("/") || link.startsWith("http") || link.contains("/");
    }

}
