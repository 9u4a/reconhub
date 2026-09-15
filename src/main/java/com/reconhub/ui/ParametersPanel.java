package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.analysis.ParameterClassifier;
import com.reconhub.core.DataStore;
import com.reconhub.model.ParameterInfo;

import javax.swing.JComponent;
import java.awt.Component;
import java.awt.Font;
import java.util.List;

/**
 * Table of parameters, one row per (endpoint, parameter). Selecting a row shows the representative
 * request/response below. The "Class" column carries passive vulnerability-class hints derived from
 * the parameter name (recon triage only).
 */
public final class ParametersPanel extends AbstractTablePanel<ParameterInfo> {

    private static final String[] COLS =
            {"Endpoint", "Type", "Name", "Class", "Example", "Reflected", "Seen"};
    private static final int COL_CLASS = 3;
    private static final int COL_REFLECTED = 5;

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
    protected void styleCell(Component comp, ParameterInfo p, int viewColumn, boolean selected) {
        if (p == null) {
            return;
        }
        String classes = ParameterClassifier.classifyJoined(p.getName());
        boolean hasClass = !classes.isEmpty();

        if (comp instanceof JComponent jc) {
            jc.setToolTipText(viewColumn == COL_CLASS && hasClass ? classes : null);
        }

        if (!selected) {
            if (p.isReflected()) {
                comp.setForeground(SwingColors.WARN);          // reflected = XSS candidate
            } else if (hasClass && viewColumn == COL_CLASS) {
                comp.setForeground(SwingColors.LOW);           // class hint = accent
            }
        }
        boolean bold = (viewColumn == COL_REFLECTED && p.isReflected())
                || (viewColumn == COL_CLASS && hasClass);
        comp.setFont(comp.getFont().deriveFont(bold ? Font.BOLD : Font.PLAIN));
    }

    @Override
    protected void onRowSelected(ParameterInfo p) {
        if (p == null) {
            viewer.show(null);
            viewer.setInfo(" ");
            return;
        }
        viewer.show(p.getMessages());
        String classes = ParameterClassifier.classifyJoined(p.getName());
        StringBuilder sb = new StringBuilder();
        sb.append(p.getLocation().name()).append(" parameter \"").append(p.getName())
                .append("\" on ").append(p.getEndpointPath());
        if (!classes.isEmpty()) {
            sb.append("   |   class: ").append(classes);
        }
        viewer.setInfo(sb.toString());
    }

    @Override protected boolean supportsBodySearch() { return true; }

    @Override
    protected String searchableBody(ParameterInfo p) {
        return p == null ? null : MessageViewer.toSearchText(p.getMessages());
    }

    @Override protected List<ParameterInfo> supplyRows() { return store.snapshotParameters(); }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{280, 60, 160, 150, 200, 80, 55};
    }

    @Override protected Object valueAt(ParameterInfo p, int c) {
        return switch (c) {
            case 0 -> p.getEndpointPath();
            case 1 -> p.getLocation().name();
            case 2 -> p.getName();
            case 3 -> ParameterClassifier.classifyJoined(p.getName());
            case 4 -> p.getExampleValue();
            case 5 -> p.isReflected() ? "yes" : "";
            case 6 -> p.getSeen();
            default -> "";
        };
    }
}
