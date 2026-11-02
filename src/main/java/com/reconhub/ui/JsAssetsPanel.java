package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.active.MatchReplaceEngine;
import com.reconhub.active.MatchReplaceTarget;
import com.reconhub.analysis.JsRisk;
import com.reconhub.core.Bookmarks;
import com.reconhub.core.DataStore;
import com.reconhub.core.Hosts;
import com.reconhub.core.Settings;
import com.reconhub.core.TrafficIngestor;
import com.reconhub.model.Endpoint;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.SwingWorker;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.Font;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** Collected JS files, with a detail panel: metadata/preview (Info tab) and the captured
 * request/response (Response tab, when this asset came from traffic rather than a local import). */
public final class JsAssetsPanel extends AbstractTablePanel<JsAsset> {

    // 0.55.0: Secrets -> Findings (every JS finding, not just secrets) + Risk + Kind; Saved path moved
    // to the Info tab only (it's on the "Open saved file" button there).
    private static final String[] COLS =
            {"URL", "Kind", "Size (KB)", "Endpoints", "Findings", "Risk", "Preview"};
    private static final int COL_URL = 0;
    private static final int COL_RISK = 5;
    private static final int COL_PREVIEW = 6;
    private static final int RESPONSE_TAB = 1;
    /** Below this size, a JS file with no endpoints and no findings is an empty chunk (webpack runtime,
     * manifest, ...) -- hidden with the libraries. */
    static final int EMPTY_CHUNK_MAX_CHARS = 2048;

    private final DataStore store;
    private final TrafficIngestor ingestor;
    private final MessageViewer viewer;
    private final JTabbedPane detailTabs = new JTabbedPane();
    private final JTextArea detail = new JTextArea();
    private final JButton openFile = new JButton("Open saved file");
    private final JButton importJs = new JButton("Import JS file(s)…");
    private final JLabel importStatus = new JLabel(" ");
    private volatile String currentSavedPath = "";
    private DashboardPanel.Navigator navigator;
    private MatchReplaceEngine matchReplace;
    private Settings settings;
    private final JCheckBox hideNoise = new JCheckBox("Hide libraries & empty chunks", true);
    private final JsRisk.Memo riskMemo = new JsRisk.Memo();
    // url -> findings/risk, rebuilt only when the findings snapshot changes (see JsRisk.Memo).
    private Map<String, JsRisk.Stat> stats = Map.of();

    public JsAssetsPanel(DataStore store, MontoyaApi api, TrafficIngestor ingestor, Bookmarks bookmarks) {
        super(api, bookmarks);
        this.store = store;
        this.ingestor = ingestor;
        this.viewer = new MessageViewer(api);

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

        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.add(top, BorderLayout.NORTH);
        infoPanel.add(new JScrollPane(detail), BorderLayout.CENTER);

        detailTabs.addTab("Info", infoPanel);
        detailTabs.addTab("Response", viewer);
        installDetail(detailTabs, viewer);

        hideNoise.setToolTipText("Hide JS recognized as a library / vendor chunk / third-party script, and "
                + "tiny files with no endpoints or findings (view only -- nothing is deleted)");
        hideNoise.addActionListener(e -> reapplyFilter());
        addToToolbar(hideNoise);

        // MULTIPLE_INTERVAL_SELECTION (0.43.0) -- same reasoning as EndpointsPanel's (0.42.0).
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        // Riskiest file first by default (header click / Shift-multi-sort still work as usual).
        table.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(COL_RISK, SortOrder.DESCENDING)));
    }

    @Override protected boolean hasRowFilter() { return true; }

    @Override
    protected boolean rowIncluded(JsAsset a) {
        return a == null || !hideNoise.isSelected() || !isNoise(a, JsRisk.of(stats, a.getUrl()).findings());
    }

    /** Library / vendor / third-party JS, or an empty chunk. Pure/static for headless testing. */
    static boolean isNoise(JsAsset a, int findings) {
        return a.isLibrary() || (a.getSizeBytes() < EMPTY_CHUNK_MAX_CHARS
                && a.getExtractedEndpoints() == 0 && findings == 0);
    }

    @Override
    public void refreshData() {
        // Before super: valueAt()/rowIncluded() read `stats` during the table reload.
        stats = riskMemo.get(store.snapshotFindings());
        super.refreshData();
        int hidden = 0;
        for (JsAsset a : rows()) {
            if (isNoise(a, JsRisk.of(stats, a.getUrl()).findings())) {
                hidden++;
            }
        }
        String label = "Hide libraries & empty chunks (" + hidden + ")";
        if (!label.equals(hideNoise.getText())) {
            hideNoise.setText(label);
        }
    }

    /** Wires cross-tab navigation (this JS file → endpoints/findings found in it). */
    public void setNavigator(DashboardPanel.Navigator navigator) {
        this.navigator = navigator;
    }

    /** Wires the (ACTIVE) Match & Replace bulk-send action for this tab's right-click menu; called
     * once. */
    public void setMatchReplace(MatchReplaceEngine engine, Settings settings) {
        this.matchReplace = engine;
        this.settings = settings;
    }

    /** The currently-selected JS assets converted to Match & Replace's type-agnostic target shape --
     * host/path derived from the asset's own URL (JsAsset has no separate host/path fields), method
     * from the captured request. */
    private List<MatchReplaceTarget> selectedMatchReplaceTargets() {
        List<MatchReplaceTarget> out = new ArrayList<>();
        for (int view : table.getSelectedRows()) {
            JsAsset a = rowAt(view);
            if (a != null) {
                out.add(toTarget(a));
            }
        }
        return out;
    }

    private static MatchReplaceTarget toTarget(JsAsset a) {
        HttpRequestResponse rr = a.getMessages();
        String method = rr != null && rr.request() != null ? rr.request().method() : "?";
        String path = pathOf(a.getUrl());
        return new MatchReplaceTarget(a.getHost(), path, method, rr);   // cached on JsAsset (0.43.9)
    }

    private static String pathOf(String url) {
        if (url == null) {
            return "";
        }
        try {
            String p = java.net.URI.create(url).getPath();
            return p == null ? "" : p;
        } catch (RuntimeException e) {
            return "";
        }
    }

    @Override protected String rowKey(JsAsset a) { return a == null ? null : a.key(); }

    @Override
    protected void extraMenuItems(JPopupMenu menu, JsAsset a) {
        if (a == null) {
            return;
        }
        menu.addSeparator();
        addMenuItem(menu, "Copy preview", !a.getPreview().isEmpty(),
                () -> UiUtil.copyToClipboard(a.getPreview()));
        // Findings are searchable by their "Location" column (= the JS URL for a JS-sourced finding),
        // so a plain searchFor(url) filters correctly. Endpoints has no equivalent searchable column
        // for "which JS this was discovered in" (Endpoint.getOrigins() isn't a table column) -- the
        // Info tab's own "Endpoints found in this JS" list (computed the same way, onRowSelected) is
        // the only place that relationship is shown; not offered here to avoid a menu item that would
        // silently filter to zero rows.
        if (navigator != null) {
            addMenuItem(menu, "View findings from this JS", true,
                    () -> navigator.filterFindings(a.getUrl()));
        }

        if (matchReplace != null && settings != null) {
            List<MatchReplaceTarget> selected = selectedMatchReplaceTargets();
            List<MatchReplaceTarget> targets = selected.isEmpty() ? List.of(toTarget(a)) : selected;
            menu.addSeparator();
            addMenuItem(menu, "Send " + targets.size() + " selected with Match & Replace… (active)", true,
                    () -> MatchReplaceDialog.show(this, matchReplace, settings, targets));
        }
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
            viewer.show(null);
            viewer.setInfo(" ");
            detailTabs.setTitleAt(RESPONSE_TAB, "Response");
            return;
        }
        currentSavedPath = a.getSavedPath();
        openFile.setEnabled(currentSavedPath != null && !currentSavedPath.isBlank());

        viewer.show(a.getMessages());
        viewer.setInfo(a.getUrl() + "   |   " + a.getSizeBytes() + " chars   |   " + a.getSha256());
        detailTabs.setTitleAt(RESPONSE_TAB, a.getMessages() != null ? "Response ✓" : "Response");

        // 0.55.0: actionable first -- findings (severity order, each with its "Try:" hint), then the
        // endpoints this JS references, then file metadata.
        StringBuilder sb = new StringBuilder();
        sb.append(a.getUrl()).append('\n');
        if (a.isLibrary()) {
            sb.append(a.getKind()).append(" -- deep analysis skipped unless enabled in Settings > JavaScript\n");
        }
        sb.append('\n');

        List<Finding> fs = store.snapshotFindings().stream()
                .filter(f -> a.getUrl().equals(f.getLocationUrl()))
                .sorted(Comparator.comparing(Finding::getSeverity))
                .toList();
        sb.append("Findings in this JS (").append(fs.size()).append("):\n");
        for (Finding f : fs) {
            sb.append("  [").append(f.getSeverity().name()).append("] ").append(f.getType());
            if (!f.getMasked().isEmpty()) {
                sb.append(" = ").append(f.getMasked());
            }
            sb.append('\n');
            String ev = f.getEvidence();
            if (ev != null && ev.contains("Try:")) {
                sb.append("        ").append(ev.substring(ev.indexOf("Try:"))).append('\n');
            }
        }

        // hasOrigin (0.43.9), not getOrigins().contains(...) -- this runs over every endpoint in the
        // store on every row selection/arrow-key move, and hasOrigin is an O(1) lookup against the raw
        // set instead of materializing each endpoint's sorted TreeSet snapshot just to test membership.
        List<Endpoint> eps = store.snapshotEndpoints().stream()
                .filter(e -> e.hasOrigin(a.getUrl())).toList();
        sb.append("Endpoints found in this JS (").append(eps.size()).append("):\n");
        for (Endpoint e : eps) {
            sb.append("  ").append(e.getNormalizedUrl()).append('\n');
        }

        sb.append("\nSHA-256   : ").append(a.getSha256()).append('\n');
        sb.append("Size      : ").append(a.getSizeBytes()).append(" chars\n");
        sb.append("Preview   : ").append(a.getPreview().isEmpty() ? "(none)" : a.getPreview()).append('\n');
        sb.append("Saved     : ").append(a.getSavedPath().isEmpty() ? "(not saved)" : a.getSavedPath())
                .append('\n');

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

    @Override
    protected HttpRequestResponse rowMessages(JsAsset a) {
        return a == null ? null : a.getMessages();
    }

    @Override protected boolean supportsBodySearch() { return true; }

    @Override
    protected String searchableBody(JsAsset a) {
        return a == null ? null : MessageViewer.toSearchText(a.getMessages());
    }

    @Override protected List<JsAsset> supplyRows() { return store.snapshotJsAssets(); }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{320, 170, 70, 75, 70, 55, 300};
    }

    // Size (2), Endpoints (3), Findings (4), Risk (5) are numeric -- declared so the sorter compares
    // them as numbers, not lexicographically (which would put e.g. "10" before "2"). Static constant
    // (0.43.8) -- see EndpointsPanel's identical note.
    private static final Class<?>[] COLUMN_CLASSES =
            {null, null, Integer.class, Integer.class, Integer.class, Integer.class, null};

    @Override protected Class<?>[] columnClasses() {
        return COLUMN_CLASSES;
    }

    @Override protected Object valueAt(JsAsset a, int c) {
        return switch (c) {
            case COL_URL -> a.getUrl();
            case 1 -> a.getKind();
            case 2 -> (a.getSizeBytes() + 1023) / 1024;
            case 3 -> a.getExtractedEndpoints();
            case 4 -> JsRisk.of(stats, a.getUrl()).findings();
            case COL_RISK -> JsRisk.of(stats, a.getUrl()).score();
            case COL_PREVIEW -> a.getPreview();
            default -> "";
        };
    }

    @Override
    protected void styleCell(Component comp, JsAsset a, int viewColumn, boolean selected) {
        if (a == null || !(comp instanceof JComponent jc)) {
            return;
        }
        if (viewColumn == COL_PREVIEW) {
            jc.setToolTipText(a.getPreview().isEmpty() ? null : a.getPreview());
        } else if (viewColumn == COL_URL) {
            jc.setToolTipText(a.getUrl());
        }
    }
}
