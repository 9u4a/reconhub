package com.reconhub.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.reconhub.active.AuthDetector;
import com.reconhub.active.SessionProfiles;
import com.reconhub.core.TrafficIngestor;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

/**
 * Adds a "Send to ReconHub" item to Burp context menus (Proxy, Target, ...). Selected
 * request/responses are ingested regardless of scope, so the user can pull in arbitrary traffic.
 */
public final class SendToReconHubMenu implements ContextMenuItemsProvider {

    private final TrafficIngestor ingestor;
    private final SessionProfiles sessions;            // null = no session item
    private final java.util.function.Supplier<Component> owner;

    public SendToReconHubMenu(TrafficIngestor ingestor) {
        this(ingestor, null, () -> null);
    }

    /** 0.60.0: also offers "Save as ReconHub session…" (credentials auto-detected from the request). */
    public SendToReconHubMenu(TrafficIngestor ingestor, SessionProfiles sessions,
                              java.util.function.Supplier<Component> owner) {
        this.ingestor = ingestor;
        this.sessions = sessions;
        this.owner = owner;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        List<Component> items = new ArrayList<>();
        if (selected != null && !selected.isEmpty()) {
            JMenuItem item = new JMenuItem("Send to ReconHub (" + selected.size() + ")");
            item.addActionListener(e -> {
                for (HttpRequestResponse rr : selected) {
                    ingestor.ingestExternal(rr);
                }
            });
            items.add(item);
        }
        if (sessions != null) {
            HttpRequest req = null;
            if (selected != null && !selected.isEmpty()) {
                req = selected.get(0).request();
            } else if (event.messageEditorRequestResponse().isPresent()) {
                req = event.messageEditorRequestResponse().get().requestResponse().request();   // Repeater etc.
            }
            if (req != null) {
                final HttpRequest r = req;
                JMenuItem save = new JMenuItem("Save as ReconHub session…");
                save.addActionListener(e -> saveSession(r));
                items.add(save);
            }
        }
        return items.isEmpty() ? null : items;
    }

    /** Opens the session editor prefilled with the auth headers / session cookies detected on {@code req}. */
    private void saveSession(HttpRequest req) {
        List<String[]> headers = new ArrayList<>();
        for (HttpHeader h : req.headers()) {
            headers.add(new String[]{h.name(), h.value()});
        }
        List<AuthDetector.Part> parts = AuthDetector.detect(headers);
        String host = req.httpService() == null ? "" : req.httpService().host();
        SessionEditorDialog.open(owner.get(), sessions, null, parts, "request " + host);
    }
}
