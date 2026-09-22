package com.reconhub.analysis;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.core.DataStore;
import com.reconhub.core.HashUtil;
import com.reconhub.core.Settings;
import com.reconhub.export.JsFileWriter;
import com.reconhub.model.JsAsset;

import java.net.URI;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;

/**
 * Collects a JavaScript body: dedups by SHA-256, optionally writes it to disk, and mines it for
 * endpoints (LinkFinder-style) and secrets (reusing {@link SecretScanner}).
 */
public final class JsAnalyzer {

    private static final int MAX_LINKS_PER_RULE = 500;

    private final DataStore store;
    private final PatternRegistry patterns;
    private final SecretScanner secretScanner;
    private final CommentExtractor commentExtractor;
    private final SourceMapDetector sourceMapDetector;
    private final Settings settings;

    public JsAnalyzer(DataStore store, PatternRegistry patterns, SecretScanner secretScanner,
                      CommentExtractor commentExtractor, SourceMapDetector sourceMapDetector,
                      Settings settings) {
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

        if (settings.isSaveJsToDisk()) {
            Path saved = JsFileWriter.write(settings.getJsSaveDirectory(), url, sha, body);
            if (saved != null) {
                asset.setSavedPath(saved.toString());
            }
        }

        int endpoints = extractEndpoints(url, body);
        asset.setExtractedEndpoints(endpoints);

        int secrets = secretScanner.scan(body, url, messages);
        asset.setExtractedSecrets(secrets);

        sourceMapDetector.checkJsBody(url, body, messages);

        if (settings.isRunPassiveChecks()) {
            commentExtractor.extractJs(body, url, messages);
        }
    }

    private int extractEndpoints(String jsUrl, String body) {
        String host = hostOf(jsUrl);
        Set<String> seen = new HashSet<>();
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
        return seen.size();
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
