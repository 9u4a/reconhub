package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.reconhub.core.DataStore;
import com.reconhub.model.Endpoint;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPopupMenu;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

/** Table of deduplicated endpoints, with a right-click "Send to Repeater" action. */
public final class EndpointsPanel extends AbstractTablePanel<Endpoint> {

    private static final String[] COLS =
            {"Method", "Host", "Path", "Status", "Content-Type", "Params", "Source"};

    private final DataStore store;
    private final MontoyaApi api;
    private final MessageViewer viewer;

    public EndpointsPanel(DataStore store, MontoyaApi api) {
        this.store = store;
        this.api = api;
        this.viewer = new MessageViewer(api);
        installDetail(viewer);
        installContextMenu();
    }

    @Override
    protected void onRowSelected(Endpoint e) {
        if (e == null) {
            viewer.show(null);
            viewer.setInfo(" ");
            return;
        }
        viewer.show(e.getMessages());
        StringBuilder info = new StringBuilder();
        if (!e.getParamNames().isEmpty()) {
            info.append("Params: ").append(String.join(", ", e.getParamNames()));
        }
        if (!e.getOrigins().isEmpty()) {
            if (info.length() > 0) {
                info.append("   |   ");
            }
            info.append("Found in: ").append(String.join(", ", e.getOrigins()));
        }
        if (info.length() == 0) {
            info.append(e.getMethod()).append(' ').append(e.getNormalizedUrl());
        }
        viewer.setInfo(info.toString());
    }

    private void installContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem toRepeater = new JMenuItem("Send to Repeater");
        toRepeater.addActionListener(e -> sendSelectedToRepeater());
        menu.add(toRepeater);

        table.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { maybeShow(e); }
            @Override public void mouseReleased(MouseEvent e) { maybeShow(e); }
            private void maybeShow(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row >= 0 && !table.isRowSelected(row)) {
                        table.setRowSelectionInterval(row, row);
                    }
                    menu.show(table, e.getX(), e.getY());
                }
            }
        });
    }

    private void sendSelectedToRepeater() {
        Endpoint ep = rowAt(table.getSelectedRow());
        if (ep == null) {
            return;
        }
        String url = ep.getNormalizedUrl();
        if (!url.startsWith("http")) {
            JOptionPane.showMessageDialog(this,
                    "This entry is a relative/JS-discovered path and has no absolute URL:\n" + url,
                    "Cannot send to Repeater", JOptionPane.WARNING_MESSAGE);
            return;
        }
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(url);
            if (!"GET".equalsIgnoreCase(ep.getMethod()) && !"JS".equals(ep.getMethod())) {
                request = request.withMethod(ep.getMethod());
            }
            api.repeater().sendToRepeater(request, "ReconHub: " + ep.getPath());
        } catch (RuntimeException ex) {
            JOptionPane.showMessageDialog(this, "Failed to send: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    @Override protected List<Endpoint> supplyRows() { return store.snapshotEndpoints(); }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{60, 160, 340, 60, 160, 60, 90};
    }

    @Override protected Object valueAt(Endpoint e, int c) {
        return switch (c) {
            case 0 -> e.getMethod();
            case 1 -> e.getHost();
            case 2 -> e.getPath();
            case 3 -> e.getLastStatusCode() == 0 ? "" : e.getLastStatusCode();
            case 4 -> shortCt(e.getContentType());
            case 5 -> e.getParamCount();
            case 6 -> String.join(",", e.getSources());
            default -> "";
        };
    }

    private static String shortCt(String ct) {
        return ct == null ? "" : ct.split(";")[0].trim();
    }
}
