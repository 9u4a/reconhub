package com.reconhub.analysis;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.core.DataStore;
import com.reconhub.core.HashUtil;
import com.reconhub.model.Finding;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts developer comments from HTML and JS bodies and reports the interesting ones (those
 * containing keywords, paths or URLs) as {@link Finding}s. Deduplicated by content hash.
 */
public final class CommentExtractor {

    // 0.43.7: the lazy ".*?" here had no span bound and no cheap pre-check -- an unterminated "<!--" (or
    // "/*") partway through a large body makes the lazy quantifier expand one char at a time all the
    // way to end-of-input (DOTALL, so newlines don't stop it either) before giving up at that start
    // position, then retry from the next "<!--"/"/*" -- O(occurrences x remaining body length) in the
    // worst case. This file used hardcoded Patterns, not the JSON rule files the 0.41.2 ReDoS audit
    // covered, so it was never in scope for that pass. Bounding the capture span turns the worst case
    // into O(occurrences x bound) -- a genuinely longer comment just doesn't match, same trade-off as
    // this class's own MAX_LEN/MAX_PER_BODY caps already make elsewhere.
    private static final int MAX_COMMENT_SPAN = 20_000;
    private static final Pattern HTML_COMMENT =
            Pattern.compile("<!--(.{0," + MAX_COMMENT_SPAN + "}?)-->", Pattern.DOTALL);
    private static final Pattern JS_BLOCK =
            Pattern.compile("/\\*(.{0," + MAX_COMMENT_SPAN + "}?)\\*/", Pattern.DOTALL);
    // Line comment not preceded by ':' (avoids http://), captured to end of line.
    private static final Pattern JS_LINE = Pattern.compile("(?<![:/])//([^\\n\\r]{0,300})");
    private static final Pattern INTERESTING = Pattern.compile(
            "(?i)(todo|fixme|hack|xxx|bug|deprecated|password|passwd|pwd|secret|api[_-]?key|token|"
                    + "backdoor|debug|username|user\\b|admin|internal|/[a-z0-9._/-]{2,}|https?://)");

    private static final int MAX_PER_BODY = 50;   // match attempts per body, interesting or not
    private static final int MAX_LEN = 300;
    // 0.43.7: no ceiling previously existed on body size scanned here.
    private static final int MAX_SCAN_CHARS = 10_000_000;

    private final DataStore store;

    public CommentExtractor(DataStore store) {
        this.store = store;
    }

    public int extractHtml(String body, String url, HttpRequestResponse messages) {
        // Cheap bail-out (0.43.7): the overwhelming majority of bodies have no "<!--" at all, so this
        // skips building a Matcher and running the (now-bounded, but still not free) regex entirely.
        if (body == null || !body.contains("<!--")) {
            return 0;
        }
        return scan(HTML_COMMENT, body, url, "HTML Comment", messages);
    }

    public int extractJs(String body, String url, HttpRequestResponse messages) {
        if (body == null) {
            return 0;
        }
        int n = body.contains("/*") ? scan(JS_BLOCK, body, url, "JS Comment", messages) : 0;
        n += body.contains("//") ? scan(JS_LINE, body, url, "JS Comment", messages) : 0;
        return n;
    }

    private int scan(Pattern p, String body, String url, String type, HttpRequestResponse messages) {
        if (body == null || body.isEmpty() || body.length() > MAX_SCAN_CHARS) {
            return 0;
        }
        int found = 0;
        int examined = 0;   // match ATTEMPTS, not new findings -- see MAX_PER_BODY
        Matcher m = p.matcher(body);
        while (examined < MAX_PER_BODY && m.find()) {
            examined++;
            String text = m.group(1) == null ? "" : m.group(1).trim();
            if (text.length() < 4 || !INTERESTING.matcher(text).find()) {
                continue;
            }
            String shown = text.length() > MAX_LEN ? text.substring(0, MAX_LEN) + "…" : text;
            // Dedup by content hash so the same comment across pages collapses to one row.
            Finding f = new Finding(type, Finding.Severity.INFO,
                    HashUtil.sha256(type + text), url, shown, false);
            f.setMessages(messages);
            if (store.recordFinding(f)) {
                found++;
            }
        }
        return found;
    }
}
