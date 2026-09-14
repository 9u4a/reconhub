package com.reconhub.ui;

import com.reconhub.core.DataStore;
import com.reconhub.model.TechInfo;

import java.util.List;

/** Table of per-host technologies and missing security headers. */
public final class TechPanel extends AbstractTablePanel<TechInfo> {

    private static final String[] COLS = {"Host", "Technologies", "Missing security headers"};

    private final DataStore store;

    public TechPanel(DataStore store) {
        this.store = store;
    }

    @Override protected List<TechInfo> supplyRows() { return store.snapshotTech(); }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{220, 400, 400};
    }

    @Override protected Object valueAt(TechInfo t, int c) {
        return switch (c) {
            case 0 -> t.getHost();
            case 1 -> String.join(", ", t.getTechnologies());
            case 2 -> String.join(", ", t.getMissingSecurityHeaders());
            default -> "";
        };
    }
}
