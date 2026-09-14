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

    private static final Pattern HTML_COMMENT = Pattern.compile("<!--(.*?)-->", Pattern.DOTALL);
    private static final Pattern JS_BLOCK = Pattern.compile("/\\*(.*?)\\*/", Pattern.DOTALL);
    // Line comment not preceded by ':' (avoids http://), captured to end of line.
    private static final Pattern JS_LINE = Pattern.compile("(?<![:/])//([^\\n\\r]{0,300})");
    private static final Pattern INTERESTING = Pattern.compile(
            "(?i)(todo|fixme|hack|xxx|bug|deprecated|password|passwd|pwd|secret|api[_-]?key|token|"
                    + "backdoor|debug|username|user\\b|admin|internal|/[a-z0-9._/-]{2,}|https?://)");

    private static final int MAX_PER_BODY = 50;
    private static final int MAX_LEN = 300;

    private final DataStore store;

    public CommentExtractor(DataStore store) {
        this.store = store;
    }

    public int extractHtml(String body, String url, HttpRequestResponse messages) {
        return scan(HTML_COMMENT, body, url, "HTML Comment", messages);
    }

    public int extractJs(String body, String url, HttpRequestResponse messages) {
        int n = scan(JS_BLOCK, body, url, "JS Comment", messages);
        n += scan(JS_LINE, body, url, "JS Comment", messages);
        return n;
    }

    private int scan(Pattern p, String body, String url, String type, HttpRequestResponse messages) {
        if (body == null || body.isEmpty()) {
            return 0;
        }
        int found = 0;
        Matcher m = p.matcher(body);
        while (m.find() && found < MAX_PER_BODY) {
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
