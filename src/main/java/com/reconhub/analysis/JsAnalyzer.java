package com.reconhub.analysis;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.core.DataStore;
import com.reconhub.core.HashUtil;
import com.reconhub.core.Settings;
import com.reconhub.export.JsFileWriter;
import com.reconhub.model.JsAsset;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;

/**
 * Collects a JavaScript body: dedups by SHA-256, optionally writes it to disk, and mines it for
 * endpoints (LinkFinder-style) and secrets (reusing {@link SecretScanner}).
 */
public final class JsAnalyzer {

    private static final int MAX_LINKS_PER_RULE = 500;
    private static final int PREVIEW_MAX = 160;
    private static final int PREVIEW_SAMPLES = 3;

    private final MontoyaApi api;   // nullable (headless tests); used only to log a save failure
    private final DataStore store;
    private final PatternRegistry patterns;
    private final SecretScanner secretScanner;
    private final CommentExtractor commentExtractor;
    private final SourceMapDetector sourceMapDetector;
    private final Settings settings;
    private final AtomicInteger saveFailures = new AtomicInteger();

    public JsAnalyzer(MontoyaApi api, DataStore store, PatternRegistry patterns,
                      SecretScanner secretScanner, CommentExtractor commentExtractor,
                      SourceMapDetector sourceMapDetector, Settings settings) {
        this.api = api;
        this.store = store;
        this.patterns = patterns;
        this.secretScanner = secretScanner;
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

        if (settings.isSaveJsToDisk()) {
            try {
                asset.setSavedPath(
                        JsFileWriter.write(settings.getJsSaveDirectory(), url, sha, body).toString());
            } catch (IOException | RuntimeException e) {
                logSaveFailure(e);
            }
        }

        List<String> links = extractEndpoints(url, body);
        asset.setExtractedEndpoints(links.size());
        asset.setPreview(buildPreview(links, body));

        int secrets = secretScanner.scan(body, url, messages);
        asset.setExtractedSecrets(secrets);

        sourceMapDetector.checkJsBody(url, body, messages);

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
    private List<String> extractEndpoints(String jsUrl, String body) {
        String host = hostOf(jsUrl);
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
                String linkHost = link.startsWith("http") ? hostOf(link) : host;
                store.recordEndpoint("JS", linkHost, link, link, 0, "", "js",
                        Set.of(), null, Set.of(jsUrl));
            }
        }
        return new ArrayList<>(seen);
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
        // Drop obvious noise: mime types, pure file extensions, template placeholders.
        String lower = link.toLowerCase();
        if (lower.matches("[a-z]+/[a-z0-9.+-]+")) {   // e.g. "text/html", "image/png"
            return false;
        }
        if (link.contains("${") || link.contains("{{") || link.contains("<%")) {
            return false;
        }
        return link.startsWith("/") || link.startsWith("http") || link.contains("/");
    }

    private static String hostOf(String url) {
        try {
            URI uri = URI.create(url);
            return uri.getHost() != null ? uri.getHost() : "";
        } catch (RuntimeException e) {
            return "";
        }
    }
}
