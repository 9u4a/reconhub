package com.reconhub.ui;

import com.reconhub.core.DataStore;
import com.reconhub.model.Finding;

import java.util.List;

/** Table of secret / sensitive-information findings, most severe first. */
public final class FindingsPanel extends AbstractTablePanel<Finding> {

    private static final String[] COLS =
            {"Severity", "Type", "Value", "Location", "Evidence", "Seen"};

    private final DataStore store;

    public FindingsPanel(DataStore store) {
        this.store = store;
    }

    @Override protected List<Finding> supplyRows() { return store.snapshotFindings(); }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{80, 160, 200, 280, 320, 50};
    }

    @Override protected Object valueAt(Finding f, int c) {
        return switch (c) {
            case 0 -> f.getSeverity().name();
            case 1 -> f.getType();
            case 2 -> f.getMasked();
            case 3 -> f.getLocationUrl();
            case 4 -> f.getEvidence();
            case 5 -> f.getTimesSeen();
            default -> "";
        };
    }
}
