package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.core.DataStore;
import com.reconhub.model.Finding;

import javax.swing.JComponent;
import java.awt.Component;
import java.awt.Font;
import java.util.List;

/** Findings table with the request/response viewer and severity color-coding. */
public final class FindingsPanel extends AbstractTablePanel<Finding> {

    private static final String[] COLS =
            {"Severity", "Type", "Value", "Location", "Evidence", "Seen"};

    private final DataStore store;
    private final MessageViewer viewer;

    public FindingsPanel(DataStore store, MontoyaApi api) {
        super(api);
        this.store = store;
        this.viewer = new MessageViewer(api);
        installDetail(viewer);
    }

    @Override
    protected void onRowSelected(Finding f) {
        if (f == null) {
            viewer.show(null);
            viewer.setInfo(" ");
            return;
        }
        viewer.show(f.getMessages());
        StringBuilder sb = new StringBuilder();
        sb.append('[').append(f.getSeverity().name()).append("] ").append(f.getType());
        String value = fullValue(f);
        if (!value.isEmpty()) {
            sb.append("  —  ").append(value);
        }
        sb.append("   |   ").append(f.getLocationUrl())
                .append("   |   seen ").append(f.getTimesSeen());
        if (f.getEvidence() != null && !f.getEvidence().isBlank()) {
            sb.append("   |   ").append(f.getEvidence());
        }
        viewer.setInfo(sb.toString());
    }

    @Override
    protected HttpRequestResponse rowMessages(Finding f) {
        return f == null ? null : f.getMessages();
    }

    @Override
    protected String rowUrl(Finding f) {
        return f != null && f.getLocationUrl() != null
                && f.getLocationUrl().startsWith("http") ? f.getLocationUrl() : null;
    }

    @Override
    protected void styleCell(Component comp, Finding f, int viewColumn, boolean selected) {
        if (f == null) {
            return;
        }
        if (!selected) {
            comp.setForeground(SwingColors.severityFg(f.getSeverity()));
        }
        // Emphasize the Severity column in bold.
        comp.setFont(comp.getFont().deriveFont(viewColumn == 0 ? Font.BOLD : Font.PLAIN));
        // Hover tooltip carries the full, untruncated text so a narrow column hides nothing.
        if (comp instanceof JComponent jc) {
            String tip = switch (viewColumn) {
                case 2 -> fullValue(f);
                case 3 -> f.getLocationUrl();
                case 4 -> f.getEvidence();
                default -> null;
            };
            jc.setToolTipText(tip == null || tip.isBlank() ? null : tip);
        }
    }

    /** Full (unmasked) matched value for display/copy; empty for non-secret findings. */
    private static String fullValue(Finding f) {
        return f.isSensitive() && f.getRawMatch() != null ? f.getRawMatch() : "";
    }

    @Override protected List<Finding> supplyRows() { return store.snapshotFindings(); }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{80, 170, 320, 260, 300, 50};
    }

    @Override protected Object valueAt(Finding f, int c) {
        return switch (c) {
            case 0 -> f.getSeverity().name();
            case 1 -> f.getType();
            case 2 -> fullValue(f);
            case 3 -> f.getLocationUrl();
            case 4 -> f.getEvidence();
            case 5 -> f.getTimesSeen();
            default -> "";
        };
    }
}
