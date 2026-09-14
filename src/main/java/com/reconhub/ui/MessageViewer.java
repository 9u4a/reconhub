package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import java.awt.BorderLayout;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A read-only Request | Response viewer built from Burp's own message editors, plus a header line
 * for extra context (parameter names, JS origin, ...). Falls back to a plain label if the editors
 * cannot be created (e.g. outside the Burp runtime).
 */
public final class MessageViewer extends JPanel {

    private final JLabel info = new JLabel(" ");
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private final HttpRequest emptyRequest = HttpRequest.httpRequest("");
    private final HttpResponse emptyResponse = HttpResponse.httpResponse();

    public MessageViewer(MontoyaApi api) {
        setLayout(new BorderLayout());
        info.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        add(info, BorderLayout.NORTH);

        try {
            requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
            responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
            JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                    requestEditor.uiComponent(), responseEditor.uiComponent());
            split.setResizeWeight(0.5);
            split.setContinuousLayout(true);
            add(split, BorderLayout.CENTER);
        } catch (RuntimeException e) {
            add(new JLabel("Message editors unavailable: " + e.getMessage()), BorderLayout.CENTER);
        }
    }

    /** Sets the header context line shown above the editors. */
    public void setInfo(String text) {
        info.setText(text == null || text.isBlank() ? " " : text);
    }

    /** Highlights {@code expr} inside both editors (empty clears the highlight). */
    public void setSearchExpression(String expr) {
        String e = expr == null ? "" : expr;
        try {
            if (requestEditor != null) {
                requestEditor.setSearchExpression(e);
            }
            if (responseEditor != null) {
                responseEditor.setSearchExpression(e);
            }
        } catch (RuntimeException ignored) {
            // some Burp versions reject empty/odd expressions; ignore
        }
    }

    /** Shows the given request/response pair; clears the editors when {@code rr} has none. */
    public void show(HttpRequestResponse rr) {
        if (requestEditor == null || responseEditor == null) {
            return;
        }
        HttpRequest req = rr != null ? rr.request() : null;
        HttpResponse resp = rr != null ? rr.response() : null;
        requestEditor.setRequest(req != null ? req : emptyRequest);
        responseEditor.setResponse(resp != null ? resp : emptyResponse);
    }

    private static final Pattern CHARSET_PARAM =
            Pattern.compile("(?i)charset\\s*=\\s*\"?([A-Za-z0-9_\\-:.]+)");

    /**
     * Flattens a request/response into searchable text (URL, headers, and both bodies) so a "Body"
     * search can match content that never appears in the table columns. Returns null when there is
     * nothing to search.
     *
     * <p>Bodies are decoded from their raw bytes using the {@code Content-Type} charset (default
     * UTF-8) rather than {@code bodyToString()}, which byte-maps multibyte text and would break
     * Korean/other non-ASCII search.
     */
    public static String toSearchText(HttpRequestResponse rr) {
        if (rr == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        HttpRequest req = rr.request();
        if (req != null) {
            sb.append(req.method()).append(' ').append(req.path()).append('\n');
            for (HttpHeader h : req.headers()) {
                sb.append(h.name()).append(": ").append(h.value()).append('\n');
            }
            sb.append(decodeBody(req.body().getBytes(), req.headerValue("Content-Type"))).append('\n');
        }
        HttpResponse resp = rr.response();
        if (resp != null) {
            for (HttpHeader h : resp.headers()) {
                sb.append(h.name()).append(": ").append(h.value()).append('\n');
            }
            sb.append(decodeBody(resp.body().getBytes(), resp.headerValue("Content-Type")));
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private static String decodeBody(byte[] bytes, String contentType) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        return new String(bytes, charsetOf(contentType));
    }

    private static Charset charsetOf(String contentType) {
        if (contentType != null) {
            Matcher m = CHARSET_PARAM.matcher(contentType);
            if (m.find()) {
                try {
                    return Charset.forName(m.group(1).trim());
                } catch (RuntimeException ignored) {
                    // unknown/unsupported charset name -> fall through to UTF-8
                }
            }
        }
        return StandardCharsets.UTF_8;
    }
}
