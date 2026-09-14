package com.reconhub.ui;

import javax.swing.Box;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
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
 * <p>Search supports: multiple space-separated keywords (AND), {@code -term} exclusion, an optional
 * regex mode, case sensitivity, a per-field (column) scope, and — for panels that expose it via
 * {@link #searchableBody} — matching inside the request/response body (so Korean/English text that
 * only appears in the body is searchable). Typing is debounced; body text is cached per row.
 */
public abstract class AbstractTablePanel<T> extends JPanel implements Refreshable {

    // NOTE: `rows` MUST be initialized before `table`, because `new JTable(model)` immediately
    // queries model.getRowCount() -> rows.size(). Field initializers run in declaration order.
    private List<T> rows = new ArrayList<>();
    private final Model model = new Model();
    protected final JTable table = new JTable(model);
    private final TableRowSorter<Model> sorter = new TableRowSorter<>(model);

    private final JTextField searchField = new JTextField(30);
    private final JComboBox<String> fieldBox = new JComboBox<>();
    private final JCheckBox bodyBox = new JCheckBox("Body", true);
    private final JCheckBox regexBox = new JCheckBox(".*", false);
    private final JCheckBox caseBox = new JCheckBox("Aa", false);
    private final JLabel countLabel = new JLabel("0 rows");
    private final JScrollPane scrollPane = new JScrollPane(table);

    private final Timer debounce = new Timer(200, e -> applySearch());
    private final Map<T, String> bodyCache = new IdentityHashMap<>();

    protected AbstractTablePanel() {
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
        add(scrollPane, BorderLayout.CENTER);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onRowSelected(rowAt(table.getSelectedRow()));
            }
        });

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
        remove(scrollPane);
        scrollPane.setMinimumSize(new Dimension(0, 0));
        scrollPane.setPreferredSize(new Dimension(100, 200));
        detail.setMinimumSize(new Dimension(0, 0));
        detail.setPreferredSize(new Dimension(100, 440));
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, scrollPane, detail);
        split.setResizeWeight(0.3);          // extra space favors the viewer
        split.setContinuousLayout(true);
        add(split, BorderLayout.CENTER);
        revalidate();
    }

    /** Called when the table selection changes; {@code row} may be null. Default: no-op. */
    protected void onRowSelected(T row) {
        // subclasses override
    }

    /**
     * Text to include in "Body" searches for a row (e.g. request+response). Null = none.
     * Subclasses that hold an {@code HttpRequestResponse} override this.
     */
    protected String searchableBody(T row) {
        return null;
    }

    /** Whether this panel can search request/response bodies (shows the "Body" toggle). */
    protected boolean supportsBodySearch() {
        return false;
    }

    /** Optional extra components placed on the search row. */
    protected void addToToolbar(Component c) {
        ((JPanel) getComponent(0)).add(c);
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

        if (includes.isEmpty() && excludes.isEmpty()) {
            sorter.setRowFilter(null);
            updateCount();
            return;
        }
        sorter.setRowFilter(new SearchFilter(includes, excludes, field, useBody));
        updateCount();
    }

    private static Pattern compile(String term, boolean regex, int flags) {
        try {
            return Pattern.compile(regex ? term : Pattern.quote(term), flags);
        } catch (PatternSyntaxException e) {
            return Pattern.compile(Pattern.quote(term), flags);   // bad regex -> literal fallback
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

    /** Preferred column widths; may return {@code null} for defaults. */
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
