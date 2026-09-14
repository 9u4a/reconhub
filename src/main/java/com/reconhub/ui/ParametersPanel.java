package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.core.DataStore;
import com.reconhub.model.ParameterInfo;

import java.util.List;

/**
 * Table of parameters, one row per (endpoint, parameter). Selecting a row shows the representative
 * request/response below.
 */
public final class ParametersPanel extends AbstractTablePanel<ParameterInfo> {

    private static final String[] COLS =
            {"Endpoint", "Type", "Name", "Example", "Reflected", "Seen"};

    private final DataStore store;
    private final MessageViewer viewer;

    public ParametersPanel(DataStore store, MontoyaApi api) {
        super(api);
        this.store = store;
        this.viewer = new MessageViewer(api);
        installDetail(viewer);
    }

    @Override
    protected HttpRequestResponse rowMessages(ParameterInfo p) {
        return p == null ? null : p.getMessages();
    }

    @Override
    protected String rowUrl(ParameterInfo p) {
        HttpRequestResponse rr = p == null ? null : p.getMessages();
        return rr != null && rr.request() != null ? rr.request().url() : null;
    }

    @Override
    protected void styleCell(java.awt.Component comp, ParameterInfo p, int viewColumn, boolean selected) {
        if (p == null || !p.isReflected()) {
            return;
        }
        // Reflected value = potential XSS candidate: emphasize.
        if (!selected) {
            comp.setForeground(SwingColors.WARN);
        }
        if (viewColumn == 4) {   // "Reflected" column
            comp.setFont(comp.getFont().deriveFont(java.awt.Font.BOLD));
        }
    }

    @Override
    protected void onRowSelected(ParameterInfo p) {
        if (p == null) {
            viewer.show(null);
            viewer.setInfo(" ");
            return;
        }
        viewer.show(p.getMessages());
        viewer.setInfo(p.getLocation().name() + " parameter \"" + p.getName()
                + "\" on " + p.getEndpointPath());
    }

    @Override protected boolean supportsBodySearch() { return true; }

    @Override
    protected String searchableBody(ParameterInfo p) {
        return p == null ? null : MessageViewer.toSearchText(p.getMessages());
    }

    @Override protected List<ParameterInfo> supplyRows() { return store.snapshotParameters(); }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{300, 70, 180, 220, 80, 60};
    }

    @Override protected Object valueAt(ParameterInfo p, int c) {
        return switch (c) {
            case 0 -> p.getEndpointPath();
            case 1 -> p.getLocation().name();
            case 2 -> p.getName();
            case 3 -> p.getExampleValue();
            case 4 -> p.isReflected() ? "yes" : "";
            case 5 -> p.getSeen();
            default -> "";
        };
    }
}
