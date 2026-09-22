package com.reconhub.core;

import burp.api.montoya.MontoyaApi;

import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Decides whether a URL should be processed: the base {@link Settings.ScopeMode} (Burp scope or all)
 * further narrowed by optional user include/exclude regexes. A URL passes when it is in the base
 * scope, matches the include regex (if set), and does not match the exclude regex (if set).
 */
public final class ScopeFilter {

    private final MontoyaApi api;
    private final Settings settings;

    // Cached compiled patterns, recompiled when the source string changes.
    private String includeSrc = "";
    private Pattern includePat;
    private String excludeSrc = "";
    private Pattern excludePat;

    private final AtomicLong scopeCheckErrors = new AtomicLong();

    public ScopeFilter(MontoyaApi api, Settings settings) {
        this.api = api;
        this.settings = settings;
    }

    public boolean inScope(String url) {
        if (!baseInScope(url)) {
            return false;
        }
        Pattern inc = includePattern();
        if (inc != null && !inc.matcher(url).find()) {
            return false;
        }
        Pattern exc = excludePattern();
        return exc == null || !exc.matcher(url).find();
    }

    private boolean baseInScope(String url) {
        if (settings.getScopeMode() == Settings.ScopeMode.ALL) {
            return true;
        }
        try {
            return api.scope().isInScope(url);
        } catch (RuntimeException e) {
            // Every ingested request passes through here -- a silent false here used to mean the whole
            // extension quietly ingested nothing with no diagnostic trail. Rate-limited (1st, then every
            // 100th) so a persistent failure doesn't flood Burp's error log with one line per request.
            long n = scopeCheckErrors.incrementAndGet();
            if (n == 1 || n % 100 == 0) {
                api.logging().logToError("ReconHub: Burp scope check failed for " + url
                        + " (treating as out of scope; failure #" + n + "): " + e);
            }
            return false;
        }
    }

    private synchronized Pattern includePattern() {
        String src = settings.getScopeIncludeRegex();
        if (!src.equals(includeSrc)) {
            includeSrc = src;
            includePat = compile(src);
        }
        return includePat;
    }

    private synchronized Pattern excludePattern() {
        String src = settings.getScopeExcludeRegex();
        if (!src.equals(excludeSrc)) {
            excludeSrc = src;
            excludePat = compile(src);
        }
        return excludePat;
    }

    private static Pattern compile(String src) {
        if (src == null || src.isBlank()) {
            return null;
        }
        try {
            return Pattern.compile(src);
        } catch (PatternSyntaxException e) {
            return null;   // invalid regex -> treat as "not set" rather than break ingestion
        }
    }
}
