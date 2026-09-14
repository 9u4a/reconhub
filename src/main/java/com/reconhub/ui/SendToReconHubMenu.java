package com.reconhub.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
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

    public SendToReconHubMenu(TrafficIngestor ingestor) {
        this.ingestor = ingestor;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected == null || selected.isEmpty()) {
            return null;
        }
        JMenuItem item = new JMenuItem("Send to ReconHub (" + selected.size() + ")");
        item.addActionListener(e -> {
            for (HttpRequestResponse rr : selected) {
                ingestor.ingestExternal(rr);
            }
        });
        List<Component> items = new ArrayList<>();
        items.add(item);
        return items;
    }
}
