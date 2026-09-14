package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import com.reconhub.core.DataStore;
import com.reconhub.model.Endpoint;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.Font;
import java.io.File;
import java.util.List;

/** Collected JS files, with a detail panel: metadata, open-file, and related endpoints/findings. */
public final class JsAssetsPanel extends AbstractTablePanel<JsAsset> {

    private static final String[] COLS =
            {"URL", "Size (B)", "Endpoints", "Secrets", "Saved path"};

    private final DataStore store;
    private final JTextArea detail = new JTextArea();
    private final JButton openFile = new JButton("Open saved file");
    private volatile String currentSavedPath = "";

    public JsAssetsPanel(DataStore store, MontoyaApi api) {
        super(api);
        this.store = store;

        detail.setEditable(false);
        detail.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        openFile.setEnabled(false);
        openFile.addActionListener(e -> openSavedFile());

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        top.add(openFile);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(top, BorderLayout.NORTH);
        panel.add(new JScrollPane(detail), BorderLayout.CENTER);
        installDetail(panel);
    }

    @Override
    protected void onRowSelected(JsAsset a) {
        if (a == null) {
            detail.setText("");
            currentSavedPath = "";
            openFile.setEnabled(false);
            return;
        }
        currentSavedPath = a.getSavedPath();
        openFile.setEnabled(currentSavedPath != null && !currentSavedPath.isBlank());

        StringBuilder sb = new StringBuilder();
        sb.append("URL       : ").append(a.getUrl()).append('\n');
        sb.append("SHA-256   : ").append(a.getSha256()).append('\n');
        sb.append("Size      : ").append(a.getSizeBytes()).append(" bytes\n");
        sb.append("Saved     : ").append(a.getSavedPath().isEmpty() ? "(not saved)" : a.getSavedPath())
                .append("\n\n");

        List<Endpoint> eps = store.snapshotEndpoints().stream()
                .filter(e -> e.getOrigins().contains(a.getUrl())).toList();
        sb.append("Endpoints found in this JS (").append(eps.size()).append("):\n");
        for (Endpoint e : eps) {
            sb.append("  ").append(e.getNormalizedUrl()).append('\n');
        }

        List<Finding> fs = store.snapshotFindings().stream()
                .filter(f -> a.getUrl().equals(f.getLocationUrl())).toList();
        sb.append("\nFindings in this JS (").append(fs.size()).append("):\n");
        for (Finding f : fs) {
            sb.append("  [").append(f.getSeverity().name()).append("] ").append(f.getType());
            if (!f.getMasked().isEmpty()) {
                sb.append(" = ").append(f.getMasked());
            }
            sb.append('\n');
        }

        detail.setText(sb.toString());
        detail.setCaretPosition(0);
    }

    private void openSavedFile() {
        try {
            if (currentSavedPath != null && !currentSavedPath.isBlank()
                    && Desktop.isDesktopSupported()) {
                Desktop.getDesktop().open(new File(currentSavedPath));
            }
        } catch (Exception ex) {
            api.logging().logToError("open JS file failed: " + ex);
        }
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
