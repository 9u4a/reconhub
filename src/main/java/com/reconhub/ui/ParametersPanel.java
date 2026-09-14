package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
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
        this.store = store;
        this.viewer = new MessageViewer(api);
        installDetail(viewer);
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
