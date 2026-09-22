package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import com.reconhub.core.DataStore;
import com.reconhub.core.TrafficIngestor;
import com.reconhub.model.Endpoint;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.Font;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/** Collected JS files, with a detail panel: metadata, open-file, and related endpoints/findings. */
public final class JsAssetsPanel extends AbstractTablePanel<JsAsset> {

    private static final String[] COLS =
            {"URL", "Size (B)", "Endpoints", "Secrets", "Saved path"};

    private final DataStore store;
    private final TrafficIngestor ingestor;
    private final JTextArea detail = new JTextArea();
    private final JButton openFile = new JButton("Open saved file");
    private final JButton importJs = new JButton("Import JS file(s)…");
    private final JLabel importStatus = new JLabel(" ");
    private volatile String currentSavedPath = "";

    public JsAssetsPanel(DataStore store, MontoyaApi api, TrafficIngestor ingestor) {
        super(api);
        this.store = store;
        this.ingestor = ingestor;

        detail.setEditable(false);
        detail.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        openFile.setEnabled(false);
        openFile.addActionListener(e -> openSavedFile());
        importJs.setToolTipText("Analyze local .js file(s) not seen in captured traffic "
                + "(passive: reads the file from disk, sends nothing to any target)");
        importJs.addActionListener(e -> importJsFiles());

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        top.add(openFile);
        top.add(importJs);
        top.add(importStatus);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(top, BorderLayout.NORTH);
        panel.add(new JScrollPane(detail), BorderLayout.CENTER);
        installDetail(panel);
    }

    private void importJsFiles() {
        JFileChooser fc = new JFileChooser(System.getProperty("user.home"));
        fc.setMultiSelectionEnabled(true);
        fc.setFileFilter(new FileNameExtensionFilter("JavaScript", "js", "mjs", "jsx", "ts"));
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File[] files = fc.getSelectedFiles();
        if (files == null || files.length == 0) {
            return;
        }
        importStatus.setText("Importing " + files.length + " file(s)…");
        AtomicInteger imported = new AtomicInteger();
        AtomicInteger skipped = new AtomicInteger();
        AtomicInteger failed = new AtomicInteger();
        new SwingWorker<Void, Void>() {
            @Override protected Void doInBackground() {
                java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(files.length);
                for (File f : files) {
                    try {
                        String body = Files.readString(f.toPath(), StandardCharsets.UTF_8);
                        String syntheticUrl = "import://" + f.getName();
                        ingestor.ingestJsFile(syntheticUrl, body, isNew -> {
                            if (isNew) {
                                imported.incrementAndGet();
                            } else {
                                skipped.incrementAndGet();
                            }
                            latch.countDown();
                        });
                    } catch (Exception ex) {
                        api.logging().logToError("JS import read failed for " + f + ": " + ex);
                        failed.incrementAndGet();
                        latch.countDown();
                    }
                }
                try {
                    latch.await();
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
                return null;
            }
            @Override protected void done() {
                StringBuilder sb = new StringBuilder();
                sb.append(imported.get()).append(" imported");
                if (skipped.get() > 0) {
                    sb.append(", ").append(skipped.get()).append(" already known (skipped)");
                }
                if (failed.get() > 0) {
                    sb.append(", ").append(failed.get()).append(" failed to read");
                }
                importStatus.setText(sb.toString());
            }
        }.execute();
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

    // Size (1), Endpoints (2), Secrets (3) are numeric -- declared so the sorter compares them as
    // numbers, not lexicographically (which would put e.g. "10" before "2").
    @Override protected Class<?>[] columnClasses() {
        return new Class<?>[]{null, Integer.class, Integer.class, Integer.class, null};
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
