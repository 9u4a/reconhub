package com.reconhub.ui;

import com.reconhub.analysis.FindingTaxonomy;
import com.reconhub.analysis.ParameterClassifier;
import com.reconhub.core.DataStore;
import com.reconhub.core.Hosts;
import com.reconhub.model.Endpoint;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;
import com.reconhub.model.ParameterInfo;
import com.reconhub.model.TechInfo;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Window;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * Cross-tab search (0.43.0) -- one query against all five data tabs at once, surfaced in a dedicated
 * results dialog. Deferred twice before this (0.36.0, 0.37.0 Tier C) specifically because it needed a
 * new aggregate-view UI; this is that UI.
 *
 * <p>Reuses {@link SearchQuery} (extracted from {@code AbstractTablePanel.applySearch} for exactly this)
 * for matching semantics, so a query behaves identically here and in any per-tab search box. Each row
 * type's haystack is built directly from its own fields (mirroring that type's own {@code valueAt()}
 * columns) rather than reusing per-panel code, since the five panels have no shared "give me a
 * searchable row" hook to call into.
 *
 * <p>"Go to" doesn't select the exact row -- it switches to the matching tab and narrows that tab's own
 * search box to a query specific enough to (in practice) leave just this one row visible, reusing the
 * existing {@link DashboardPanel.Navigator} cross-tab-jump plumbing rather than wiring new "select this
 * exact row by key" machinery through all five panels.
 */
final class GlobalSearchDialog {

    private GlobalSearchDialog() {}

    private enum Kind { ENDPOINT, PARAMETER, FINDING, JS_ASSET, TECH }

    private record Result(Kind kind, String host, String summary, String haystack, String jumpQuery) {}

    static void show(Component owner, DataStore store, DashboardPanel.Navigator navigator) {
        Window ownerWindow = SwingUtilities.getWindowAncestor(owner);
        JDialog dialog = new JDialog(ownerWindow, "ReconHub — Global search", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(0, 8));
        ((JPanel) dialog.getContentPane()).setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));

        JTextField searchField = new JTextField(40);
        JCheckBox regexBox = new JCheckBox("Regex");
        JCheckBox caseBox = new JCheckBox("Case sensitive (Aa)");
        JLabel countLabel = new JLabel(" ");

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        top.add(new JLabel("Search:"));
        top.add(searchField);
        top.add(regexBox);
        top.add(caseBox);
        dialog.add(top, BorderLayout.NORTH);

        ResultModel model = new ResultModel();
        JTable table = new JTable(model);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.getColumnModel().getColumn(0).setPreferredWidth(80);
        table.getColumnModel().getColumn(1).setPreferredWidth(160);
        table.getColumnModel().getColumn(2).setPreferredWidth(400);
        table.setDefaultRenderer(Object.class, SwingColors.stripedRenderer());
        table.setRowHeight(22);

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setPreferredSize(new Dimension(760, 420));
        dialog.add(tableScroll, BorderLayout.CENTER);

        JPanel bottom = new JPanel(new BorderLayout());
        bottom.add(countLabel, BorderLayout.WEST);
        JButton goTo = new JButton("Go to selected");
        goTo.setEnabled(false);
        JPanel bottomRight = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        bottomRight.add(goTo);
        bottom.add(bottomRight, BorderLayout.EAST);
        dialog.add(bottom, BorderLayout.SOUTH);

        // Indexed ONCE per dialog-open, not once per keystroke -- the whole point of keeping a
        // haystack per row around at all. Before this, every debounced keystroke re-copied all five
        // DataStore collections (snapshotX() always returns a fresh defensive copy) and rebuilt every
        // row's concatenated haystack string from scratch, which is exactly the "search gets laggy once
        // data accumulates" shape (same root cause class as AbstractTablePanel's body-search cache
        // being far too small -- see its field comment). A concurrent ingest while this (modal) dialog
        // is open won't be reflected until it's reopened -- an accepted trade-off, same spirit as
        // SnapshotDiffPanel not being a live view either.
        List<Result> indexed = index(store);

        Runnable[] runSearchRef = new Runnable[1];
        Timer debounce = new Timer(150, e -> runSearchRef[0].run());
        debounce.setRepeats(false);

        Runnable runSearch = () -> {
            SearchQuery query = SearchQuery.parse(searchField.getText(), regexBox.isSelected(),
                    caseBox.isSelected());
            List<Result> results = query.isEmpty() ? List.of() : filter(indexed, query);
            model.setResults(results);
            countLabel.setText(results.size() + " result(s)");
            goTo.setEnabled(false);
        };
        runSearchRef[0] = runSearch;

        DocumentListener onChange = new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { debounce.restart(); }
            @Override public void removeUpdate(DocumentEvent e) { debounce.restart(); }
            @Override public void changedUpdate(DocumentEvent e) { debounce.restart(); }
        };
        searchField.getDocument().addDocumentListener(onChange);
        regexBox.addActionListener(e -> runSearch.run());
        caseBox.addActionListener(e -> runSearch.run());

        Runnable goToSelected = () -> {
            int row = table.getSelectedRow();
            if (row < 0) {
                return;
            }
            Result r = model.resultAt(row);
            dialog.dispose();
            jump(navigator, r);
        };
        goTo.addActionListener(e -> goToSelected.run());
        table.getSelectionModel().addListSelectionListener(e -> goTo.setEnabled(table.getSelectedRow() >= 0));
        table.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    goToSelected.run();
                }
            }
        });

        runSearch.run();   // initial (empty query -> no results, matching the empty-haystack convention)
        dialog.pack();
        dialog.setLocationRelativeTo(ownerWindow);
        searchField.requestFocusInWindow();
        dialog.setVisible(true);
    }

    private static void jump(DashboardPanel.Navigator navigator, Result r) {
        switch (r.kind()) {
            case ENDPOINT -> navigator.filterEndpoints(r.jumpQuery());
            case PARAMETER -> navigator.filterParameters(r.jumpQuery());
            case FINDING -> navigator.filterFindings(r.jumpQuery());
            case JS_ASSET -> navigator.filterJsAssets(r.jumpQuery());
            case TECH -> navigator.filterTech(r.jumpQuery());
        }
    }

    /** Builds one {@link Result} (haystack included) per row across all five collections, unfiltered --
     * called once per dialog-open (see {@link #show}'s comment on why). {@link #filter} does the actual
     * per-keystroke work against this already-built list. */
    private static List<Result> index(DataStore store) {
        List<Result> out = new ArrayList<>();
        for (Endpoint e : store.snapshotEndpoints()) {
            String hay = e.getMethod() + " " + e.getHost() + " " + e.getPath() + " "
                    + e.getLastStatusCode() + " " + e.getContentType() + " " + e.authStatus() + " "
                    + String.join(",", e.getSources());
            out.add(new Result(Kind.ENDPOINT, e.getHost(),
                    e.getMethod() + " " + e.getPath() + "  [" + e.getLastStatusCode() + "]",
                    hay, e.getHost() + " " + e.getPath()));
        }
        for (ParameterInfo p : store.snapshotParameters()) {
            String cls = ParameterClassifier.classifyJoined(p.getName());
            String hay = p.getHost() + " " + p.getEndpointPath() + " " + p.getLocation().name() + " "
                    + p.getName() + " " + p.getExampleValue() + " " + cls;
            out.add(new Result(Kind.PARAMETER, p.getHost(),
                    p.getLocation().name() + " " + p.getName() + " on " + p.getEndpointPath(),
                    hay, p.getEndpointPath() + " " + p.getName()));
        }
        for (Finding f : store.snapshotFindings()) {
            String host = f.getHost();   // cached on Finding itself (0.43.9), not reparsed here
            String hay = f.getSeverity().name() + " " + FindingTaxonomy.labelOf(f.getType()) + " "
                    + f.getType() + " " + f.getMasked() + " " + f.getLocationUrl() + " " + f.getEvidence();
            out.add(new Result(Kind.FINDING, host,
                    "[" + f.getSeverity().name() + "] " + f.getType(),
                    hay, host + " " + f.getType()));
        }
        for (JsAsset a : store.snapshotJsAssets()) {
            String hay = a.getUrl() + " " + a.getPreview() + " " + a.getSavedPath();
            out.add(new Result(Kind.JS_ASSET, a.getHost(), a.getUrl(), hay, a.getUrl()));   // cached (0.43.9)
        }
        for (TechInfo t : store.snapshotTech()) {
            String hay = t.getHost() + " " + String.join(",", t.getTechnologies()) + " "
                    + String.join(",", t.getMissingSecurityHeaders());
            out.add(new Result(Kind.TECH, t.getHost(),
                    String.join(", ", t.getTechnologies()), hay, t.getHost()));
        }
        return out;
    }

    /** The actual per-keystroke work: just a haystack match against an already-built index, no
     * DataStore access or string-building. */
    private static List<Result> filter(List<Result> indexed, SearchQuery query) {
        List<Result> out = new ArrayList<>();
        for (Result r : indexed) {
            if (query.matches(r.haystack())) {
                out.add(r);
            }
        }
        return out;
    }

    private static final class ResultModel extends AbstractTableModel {
        private List<Result> results = List.of();

        void setResults(List<Result> results) {
            this.results = results;
            fireTableDataChanged();
        }

        Result resultAt(int row) { return results.get(row); }

        @Override public int getRowCount() { return results.size(); }
        @Override public int getColumnCount() { return 3; }
        @Override public String getColumnName(int c) {
            return switch (c) { case 0 -> "Type"; case 1 -> "Host"; default -> "Summary"; };
        }
        @Override public Object getValueAt(int row, int col) {
            Result r = results.get(row);
            return switch (col) {
                case 0 -> switch (r.kind()) {
                    case ENDPOINT -> "Endpoint";
                    case PARAMETER -> "Parameter";
                    case FINDING -> "Finding";
                    case JS_ASSET -> "JS Asset";
                    case TECH -> "Tech";
                };
                case 1 -> r.host();
                default -> r.summary();
            };
        }
    }
}
