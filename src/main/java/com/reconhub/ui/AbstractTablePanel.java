package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Base class for the data tabs: a Search bar on top, a sortable/searchable {@link JTable} below,
 * and a row count. Subclasses supply the rows, column names and cell values.
 *
 * <p>Adds a shared right-click menu (copy cell/URL, open in browser, send to Repeater/Intruder)
 * driven by the {@link #rowUrl}/{@link #rowMessages} hooks, and highlights the current search term
 * inside the message viewer when one is installed.
 */
public abstract class AbstractTablePanel<T> extends JPanel implements Refreshable {

    protected final MontoyaApi api;

    // NOTE: `rows` MUST be initialized before `table`, because `new JTable(model)` immediately
    // queries model.getRowCount() -> rows.size(). Field initializers run in declaration order.
    private List<T> rows = new ArrayList<>();
    private final Model model = new Model();
    protected final JTable table = new JTable(model);
    // Sorting cycles ascending -> descending -> unsorted (default order) on repeated header clicks.
    private final TableRowSorter<Model> sorter = new TableRowSorter<>(model) {
        @Override
        public void toggleSortOrder(int column) {
            List<? extends SortKey> keys = getSortKeys();
            if (!keys.isEmpty() && keys.get(0).getColumn() == column) {
                SortOrder cur = keys.get(0).getSortOrder();
                if (cur == SortOrder.ASCENDING) {
                    setSortKeys(List.of(new RowSorter.SortKey(column, SortOrder.DESCENDING)));
                    return;
                }
                if (cur == SortOrder.DESCENDING) {
                    setSortKeys(null);   // third click: back to unsorted
                    return;
                }
            }
            setSortKeys(List.of(new RowSorter.SortKey(column, SortOrder.ASCENDING)));
        }
    };

    private final JTextField searchField = new JTextField(30);
    private final JComboBox<String> fieldBox = new JComboBox<>();
    private final JCheckBox bodyBox = new JCheckBox("Body", true);
    private final JCheckBox regexBox = new JCheckBox(".*", false);
    private final JCheckBox caseBox = new JCheckBox("Aa", false);
    private final JLabel countLabel = new JLabel("0 rows");
    private final JScrollPane scrollPane = new JScrollPane(table);

    private final Timer debounce = new Timer(200, e -> applySearch());
    private final Map<T, String> bodyCache = new IdentityHashMap<>();
    private MessageViewer viewer;   // set by installDetail when the detail is a MessageViewer

    protected AbstractTablePanel(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout());
        debounce.setRepeats(false);

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 6));
        top.add(new JLabel("Search:"));
        top.add(searchField);
        fieldBox.addItem("All");
        for (String c : columns()) {
            fieldBox.addItem(c);
        }
        top.add(fieldBox);
        bodyBox.setVisible(supportsBodySearch());
        top.add(bodyBox);
        top.add(regexBox);
        top.add(caseBox);
        JButton csvButton = new JButton("CSV…");
        csvButton.setToolTipText("Export the current (filtered/sorted) view to CSV");
        csvButton.addActionListener(e -> exportCsv());
        top.add(csvButton);
        top.add(Box.createHorizontalStrut(10));
        top.add(countLabel);
        add(top, BorderLayout.NORTH);

        bodyBox.setToolTipText("Search inside request/response body (where available)");
        regexBox.setToolTipText("Regular-expression mode");
        caseBox.setToolTipText("Case sensitive");
        searchField.setToolTipText("Space = AND, -term to exclude. e.g.  admin -logout");

        table.setRowSorter(sorter);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setFillsViewportHeight(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setDefaultRenderer(Object.class, new StyledRenderer());
        add(scrollPane, BorderLayout.CENTER);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onRowSelected(rowAt(table.getSelectedRow()));
                highlightViewer();
            }
        });
        installContextMenu();

        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { debounce.restart(); }
            public void removeUpdate(DocumentEvent e) { debounce.restart(); }
            public void changedUpdate(DocumentEvent e) { debounce.restart(); }
        });
        fieldBox.addActionListener(e -> applySearch());
        bodyBox.addActionListener(e -> applySearch());
        regexBox.addActionListener(e -> applySearch());
        caseBox.addActionListener(e -> applySearch());
    }

    /**
     * Replaces the plain table view with a vertical split: table on top, {@code detail} below.
     * The detail (request/response viewer) gets the larger default share and is resizable.
     */
    protected void installDetail(Component detail) {
        installDetail(detail, detail instanceof MessageViewer mv ? mv : null);
    }

    /**
     * Same as {@link #installDetail(Component)}, but for a composite {@code detail} that embeds a
     * {@link MessageViewer} — pass the viewer so search-term highlighting still targets it.
     */
    protected void installDetail(Component detail, MessageViewer viewerForHighlight) {
        if (viewerForHighlight != null) {
            this.viewer = viewerForHighlight;
        }
        remove(scrollPane);
        scrollPane.setMinimumSize(new Dimension(0, 0));
        scrollPane.setPreferredSize(new Dimension(100, 200));
        detail.setMinimumSize(new Dimension(0, 0));
        detail.setPreferredSize(new Dimension(100, 440));
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, scrollPane, detail);
        split.setResizeWeight(0.3);
        split.setContinuousLayout(true);
        add(split, BorderLayout.CENTER);
        revalidate();
    }

    /** Called when the table selection changes; {@code row} may be null. Default: no-op. */
    protected void onRowSelected(T row) {
        // subclasses override
    }

    protected String searchableBody(T row) {
        return null;
    }

    protected boolean supportsBodySearch() {
        return false;
    }

    /**
     * Hook to emphasize a cell. {@code comp} already has default (or selection) colors applied;
     * override to tint it based on the row. Default: no change.
     */
    protected void styleCell(Component comp, T row, int viewColumn, boolean selected) {
        // subclasses override
    }

    /** Shared renderer that resets colors then delegates to {@link #styleCell}. */
    private final class StyledRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object value, boolean sel,
                                                       boolean focus, int row, int col) {
            Component c = super.getTableCellRendererComponent(t, value, sel, focus, row, col);
            if (sel) {
                c.setBackground(t.getSelectionBackground());
                c.setForeground(t.getSelectionForeground());
            } else {
                c.setBackground(t.getBackground());
                c.setForeground(t.getForeground());
            }
            styleCell(c, rowAt(row), col, sel);
            return c;
        }
    }

    /** Absolute URL for a row (copy/open/send). Null when the row has none. */
    protected String rowUrl(T row) {
        return null;
    }

    /** Captured request/response for a row (send to Repeater/Intruder). Null when absent. */
    protected HttpRequestResponse rowMessages(T row) {
        return null;
    }

    protected void addToToolbar(Component c) {
        ((JPanel) getComponent(0)).add(c);
    }

    /**
     * Drives the search bar programmatically (used by cross-tab navigation from the Dashboard):
     * resets to an "All"-field, non-regex, plain-substring search for {@code query}.
     */
    public void searchFor(String query) {
        if (fieldBox.getItemCount() > 0) {
            fieldBox.setSelectedIndex(0);   // "All"
        }
        regexBox.setSelected(false);
        searchField.setText(query == null ? "" : query);
        applySearch();
    }

    // ---- Context menu ---------------------------------------------------

    private void installContextMenu() {
        table.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { maybeShow(e); }
            @Override public void mouseReleased(MouseEvent e) { maybeShow(e); }
            private void maybeShow(MouseEvent e) {
                if (!e.isPopupTrigger()) {
                    return;
                }
                int row = table.rowAtPoint(e.getPoint());
                int col = table.columnAtPoint(e.getPoint());
                if (row >= 0 && !table.isRowSelected(row)) {
                    table.setRowSelectionInterval(row, row);
                }
                buildMenu(col).show(table, e.getX(), e.getY());
            }
        });
    }

    private JPopupMenu buildMenu(int viewCol) {
        JPopupMenu menu = new JPopupMenu();
        T row = rowAt(table.getSelectedRow());

        String cell = cellText(table.getSelectedRow(), viewCol);
        add(menu, "Copy cell", cell != null, () -> copy(cell));

        String url = row != null ? rowUrl(row) : null;
        add(menu, "Copy URL", url != null, () -> copy(url));
        boolean http = url != null && url.startsWith("http");
        add(menu, "Open in browser", http, () -> openBrowser(url));
        add(menu, "Send to Repeater", row != null && requestFor(row) != null,
                () -> sendToRepeater(row));
        add(menu, "Send to Intruder", row != null && requestFor(row) != null,
                () -> sendToIntruder(row));
        add(menu, "Copy as curl", row != null && requestFor(row) != null,
                () -> copy(toCurl(requestFor(row))));
        extraMenuItems(menu, row);
        return menu;
    }

    /** Hook for subclasses to append their own right-click items (a separator is added first). */
    protected void extraMenuItems(JPopupMenu menu, T row) {
        // subclasses override
    }

    /** Adds a menu item that runs {@code action} (errors are logged, never thrown to the UI). */
    protected void addMenuItem(JPopupMenu menu, String label, boolean enabled, Runnable action) {
        add(menu, label, enabled, action);
    }

    private void add(JPopupMenu menu, String label, boolean enabled, Runnable action) {
        JMenuItem item = new JMenuItem(label);
        item.setEnabled(enabled);
        item.addActionListener(e -> {
            try {
                action.run();
            } catch (RuntimeException ex) {
                api.logging().logToError("ReconHub menu action failed: " + ex);
            }
        });
        menu.add(item);
    }

    private HttpRequest requestFor(T row) {
        HttpRequestResponse rr = rowMessages(row);
        if (rr != null && rr.request() != null) {
            return rr.request();
        }
        String url = rowUrl(row);
        if (url != null && url.startsWith("http")) {
            try {
                return HttpRequest.httpRequestFromUrl(url);
            } catch (RuntimeException e) {
                return null;
            }
        }
        return null;
    }

    private void sendToRepeater(T row) {
        HttpRequest req = requestFor(row);
        if (req != null) {
            api.repeater().sendToRepeater(req, "ReconHub");
        }
    }

    private void sendToIntruder(T row) {
        HttpRequest req = requestFor(row);
        if (req != null) {
            api.intruder().sendToIntruder(req);
        }
    }

    /** Builds a copy-pasteable curl command for a captured request (no traffic is sent). */
    private static String toCurl(HttpRequest req) {
        if (req == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder("curl -X ").append(req.method())
                .append(" '").append(shq(req.url())).append('\'');
        for (HttpHeader h : req.headers()) {
            if ("Content-Length".equalsIgnoreCase(h.name())) {
                continue;   // curl sets this itself
            }
            sb.append(" -H '").append(shq(h.name() + ": " + h.value())).append('\'');
        }
        String body = req.bodyToString();
        if (body != null && !body.isEmpty()) {
            sb.append(" --data '").append(shq(body)).append('\'');
        }
        return sb.toString();
    }

    /** Escapes a value for single-quoted POSIX shell context. */
    private static String shq(String s) {
        return s == null ? "" : s.replace("'", "'\\''");
    }

    private void openBrowser(String url) {
        try {
            if (Desktop.isDesktopSupported()
                    && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI.create(url));
            }
        } catch (Exception e) {
            api.logging().logToError("open in browser failed: " + e);
        }
    }

    private static void copy(String s) {
        if (s != null) {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(s), null);
        }
    }

    private String cellText(int viewRow, int viewCol) {
        if (viewRow < 0 || viewCol < 0) {
            return null;
        }
        Object v = table.getValueAt(viewRow, viewCol);
        return v == null ? null : v.toString();
    }

    // ---- Search ---------------------------------------------------------

    private void applySearch() {
        String raw = searchField.getText().trim();
        int field = fieldBox.getSelectedIndex() - 1;   // -1 = All
        boolean useBody = bodyBox.isSelected() && field < 0;

        List<Pattern> includes = new ArrayList<>();
        List<Pattern> excludes = new ArrayList<>();
        int flags = caseBox.isSelected() ? 0 : (Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
        for (String tok : raw.split("\\s+")) {
            if (tok.isEmpty()) {
                continue;
            }
            boolean exclude = tok.length() > 1 && tok.charAt(0) == '-';
            String term = exclude ? tok.substring(1) : tok;
            if (term.isEmpty()) {
                continue;
            }
            (exclude ? excludes : includes).add(compile(term, regexBox.isSelected(), flags));
        }

        // Always install the filter so subclass row filters (rowIncluded) apply even with no search.
        sorter.setRowFilter(new SearchFilter(includes, excludes, field, useBody));
        updateCount();
        highlightViewer();
    }

    /**
     * Additional per-row visibility hook, ANDed with the search filter. Override to add quick
     * filters (e.g. by severity); call {@link #reapplyFilter()} when the criteria change.
     */
    protected boolean rowIncluded(T row) {
        return true;
    }

    /** Re-applies the search + {@link #rowIncluded} filter (call after quick-filter changes). */
    protected void reapplyFilter() {
        applySearch();
    }

    private void highlightViewer() {
        if (viewer != null) {
            viewer.setSearchExpression(firstIncludeTerm(searchField.getText().trim()));
        }
    }

    private static String firstIncludeTerm(String raw) {
        for (String tok : raw.split("\\s+")) {
            if (!tok.isEmpty() && tok.charAt(0) != '-') {
                return tok;
            }
        }
        return "";
    }

    private static Pattern compile(String term, boolean regex, int flags) {
        try {
            return Pattern.compile(regex ? term : Pattern.quote(term), flags);
        } catch (PatternSyntaxException e) {
            return Pattern.compile(Pattern.quote(term), flags);
        }
    }

    private final class SearchFilter extends RowFilter<Model, Integer> {
        private final List<Pattern> includes;
        private final List<Pattern> excludes;
        private final int field;
        private final boolean useBody;

        SearchFilter(List<Pattern> inc, List<Pattern> exc, int field, boolean useBody) {
            this.includes = inc;
            this.excludes = exc;
            this.field = field;
            this.useBody = useBody;
        }

        @Override
        public boolean include(Entry<? extends Model, ? extends Integer> entry) {
            int idx = entry.getIdentifier();
            T row = (idx >= 0 && idx < rows.size()) ? rows.get(idx) : null;
            if (!rowIncluded(row)) {
                return false;
            }
            String hay = haystack(entry);
            for (Pattern p : includes) {
                if (!p.matcher(hay).find()) {
                    return false;
                }
            }
            for (Pattern p : excludes) {
                if (p.matcher(hay).find()) {
                    return false;
                }
            }
            return true;
        }

        private String haystack(Entry<? extends Model, ? extends Integer> entry) {
            if (field >= 0 && field < entry.getValueCount()) {
                return entry.getStringValue(field);
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < entry.getValueCount(); i++) {
                sb.append(entry.getStringValue(i)).append('\n');
            }
            if (useBody) {
                int idx = entry.getIdentifier();
                if (idx >= 0 && idx < rows.size()) {
                    sb.append(bodyText(rows.get(idx)));
                }
            }
            return sb.toString();
        }
    }

    private String bodyText(T row) {
        if (row == null) {
            return "";
        }
        return bodyCache.computeIfAbsent(row, r -> {
            String s = searchableBody(r);
            return s == null ? "" : s;
        });
    }

    private void updateCount() {
        countLabel.setText(table.getRowCount() + " / " + rows.size() + " rows");
    }

    // ---- CSV export (current view) --------------------------------------

    private void exportCsv() {
        JFileChooser fc = new JFileChooser(System.getProperty("user.home"));
        fc.setSelectedFile(new File(System.getProperty("user.home"), "reconhub-table.csv"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        int cols = table.getColumnCount();
        for (int c = 0; c < cols; c++) {
            if (c > 0) {
                sb.append(',');
            }
            sb.append(csv(table.getColumnName(c)));
        }
        sb.append("\r\n");
        for (int r = 0; r < table.getRowCount(); r++) {   // view order, respects filter+sort
            for (int c = 0; c < cols; c++) {
                if (c > 0) {
                    sb.append(',');
                }
                Object v = table.getValueAt(r, c);
                sb.append(csv(v == null ? "" : v.toString()));
            }
            sb.append("\r\n");
        }
        try {
            Files.write(fc.getSelectedFile().toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));
            countLabel.setText("Saved CSV: " + fc.getSelectedFile().getName());
        } catch (IOException ex) {
            api.logging().logToError("CSV export failed: " + ex);
            countLabel.setText("CSV export failed");
        }
    }

    private static String csv(String s) {
        boolean needsQuote = s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r");
        String v = s.replace("\"", "\"\"");
        return needsQuote ? "\"" + v + "\"" : v;
    }

    /** @return the model row index for a view row (accounts for sorting/filtering). */
    protected T rowAt(int viewRow) {
        if (viewRow < 0) {
            return null;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        return (modelRow >= 0 && modelRow < rows.size()) ? rows.get(modelRow) : null;
    }

    @Override
    public void refreshData() {
        this.rows = new ArrayList<>(supplyRows());
        model.fireTableDataChanged();
        applyColumnWidths();
        updateCount();
    }

    private void applyColumnWidths() {
        int[] widths = columnWidths();
        if (widths == null) {
            return;
        }
        for (int i = 0; i < widths.length && i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
    }

    // ---- Subclass contract ----------------------------------------------

    protected abstract List<T> supplyRows();

    protected abstract String[] columns();

    protected abstract Object valueAt(T row, int column);

    protected int[] columnWidths() {
        return null;
    }

    // ---- Table model ----------------------------------------------------

    private final class Model extends AbstractTableModel {
        @Override public int getRowCount() { return rows == null ? 0 : rows.size(); }
        @Override public int getColumnCount() { return columns().length; }
        @Override public String getColumnName(int c) { return columns()[c]; }
        @Override public boolean isCellEditable(int r, int c) { return false; }
        @Override public Object getValueAt(int r, int c) {
            return (rows == null || r >= rows.size()) ? "" : valueAt(rows.get(r), c);
        }
    }
}
