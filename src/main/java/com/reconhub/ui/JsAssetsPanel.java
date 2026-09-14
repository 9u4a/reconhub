package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import com.reconhub.core.DataStore;
import com.reconhub.model.JsAsset;

import java.util.List;

/** Table of collected JavaScript files (deduplicated by content hash). */
public final class JsAssetsPanel extends AbstractTablePanel<JsAsset> {

    private static final String[] COLS =
            {"URL", "Size (B)", "Endpoints", "Secrets", "Saved path"};

    private final DataStore store;

    public JsAssetsPanel(DataStore store, MontoyaApi api) {
        super(api);
        this.store = store;
    }

    @Override
    protected String rowUrl(JsAsset a) {
        return a != null && a.getUrl() != null && a.getUrl().startsWith("http") ? a.getUrl() : null;
    }

    @Override protected List<JsAsset> supplyRows() { return store.snapshotJsAssets(); }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{380, 80, 80, 70, 360};
    }

    @Override protected Object valueAt(JsAsset a, int c) {
        return switch (c) {
            case 0 -> a.getUrl();
            case 1 -> a.getSizeBytes();
            case 2 -> a.getExtractedEndpoints();
            case 3 -> a.getExtractedSecrets();
            case 4 -> a.getSavedPath();
            default -> "";
        };
    }
}
