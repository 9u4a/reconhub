package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
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
}
