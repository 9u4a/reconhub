package com.reconhub.ui;

import javax.swing.Box;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Base class for the data tabs: a filter box on top, a sortable/filterable {@link JTable} below,
 * and a row count. Subclasses supply the rows, column names and cell values.
 */
public abstract class AbstractTablePanel<T> extends JPanel implements Refreshable {

    // NOTE: `rows` MUST be initialized before `table`, because `new JTable(model)` immediately
    // queries model.getRowCount() -> rows.size(). Field initializers run in declaration order.
    private List<T> rows = new ArrayList<>();
    private final Model model = new Model();
    protected final JTable table = new JTable(model);
    private final TableRowSorter<Model> sorter = new TableRowSorter<>(model);
    private final JTextField filterField = new JTextField(24);
    private final JLabel countLabel = new JLabel("0 rows");
    private final JScrollPane scrollPane = new JScrollPane(table);

    protected AbstractTablePanel() {
        setLayout(new BorderLayout());

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        top.add(new JLabel("Filter:"));
        top.add(filterField);
        top.add(Box.createHorizontalStrut(12));
        top.add(countLabel);
        add(top, BorderLayout.NORTH);

        table.setRowSorter(sorter);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setFillsViewportHeight(true);
        table.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        add(scrollPane, BorderLayout.CENTER);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onRowSelected(rowAt(table.getSelectedRow()));
            }
        });

        filterField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { applyFilter(); }
            public void removeUpdate(DocumentEvent e) { applyFilter(); }
            public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });
    }

    /**
     * Replaces the plain table view with a vertical split: table on top, {@code detail} below.
     * Call once from a subclass constructor when a detail/preview area is wanted.
     */
    protected void installDetail(Component detail) {
        remove(scrollPane);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, scrollPane, detail);
        split.setResizeWeight(0.5);
        split.setContinuousLayout(true);
        add(split, BorderLayout.CENTER);
        revalidate();
    }

    /** Called when the table selection changes; {@code row} may be null. Default: no-op. */
    protected void onRowSelected(T row) {
        // subclasses override
    }

    /** Optional extra components placed to the right of the filter row. */
    protected void addToToolbar(java.awt.Component c) {
        ((JPanel) getComponent(0)).add(c);
    }

    private void applyFilter() {
        String text = filterField.getText().trim();
        if (text.isEmpty()) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(text)));
        }
        updateCount();
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
