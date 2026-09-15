package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.analysis.JwtDecoder;
import com.reconhub.core.DataStore;
import com.reconhub.model.Finding;

import javax.swing.JComponent;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import java.awt.Component;
import java.awt.Font;
import java.util.List;

/** Findings table with the request/response viewer, a JWT-decode tab, and severity color-coding. */
public final class FindingsPanel extends AbstractTablePanel<Finding> {

    private static final String[] COLS =
            {"Severity", "Type", "Value", "Location", "Evidence", "Seen"};

    private final DataStore store;
    private final MessageViewer viewer;
    private final JTabbedPane detailTabs = new JTabbedPane();
    private final JTextArea jwtArea = new JTextArea();
    private static final int JWT_TAB = 1;

    public FindingsPanel(DataStore store, MontoyaApi api) {
        super(api);
        this.store = store;
        this.viewer = new MessageViewer(api);

        jwtArea.setEditable(false);
        jwtArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        jwtArea.setLineWrap(true);
        jwtArea.setWrapStyleWord(true);

        detailTabs.addTab("Message", viewer);
        detailTabs.addTab("JWT", new JScrollPane(jwtArea));
        installDetail(detailTabs, viewer);
    }

    @Override
    protected void onRowSelected(Finding f) {
        if (f == null) {
            viewer.show(null);
            viewer.setInfo(" ");
            jwtArea.setText("");
            detailTabs.setTitleAt(JWT_TAB, "JWT");
            return;
        }
        updateJwtTab(f);
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

    /** Populates the JWT tab if the finding carries a JWT (in its value or evidence). */
    private void updateJwtTab(Finding f) {
        String token = JwtDecoder.findFirst(f.getRawMatch());
        if (token == null) {
            token = JwtDecoder.findFirst(f.getEvidence());
        }
        if (token != null) {
            jwtArea.setText(JwtDecoder.decode(token));
            jwtArea.setCaretPosition(0);
            detailTabs.setTitleAt(JWT_TAB, "JWT ✓");
        } else {
            jwtArea.setText("No JWT in this finding.");
            detailTabs.setTitleAt(JWT_TAB, "JWT");
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
