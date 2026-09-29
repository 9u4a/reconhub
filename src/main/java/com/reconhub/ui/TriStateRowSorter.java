package com.reconhub.ui;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.RowSorter;
import javax.swing.RowSorter.SortKey;
import javax.swing.SortOrder;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

/**
 * A {@link TableRowSorter} whose header clicks cycle <b>ascending → descending → unsorted</b> for
 * the clicked column's own state, while still supporting Swing's normal multi-column sort (clicking a
 * new column makes it primary and keeps prior sort columns as secondary/tertiary, up to {@link
 * #getMaxSortKeys()}). Verified against the JDK 21 source
 * ({@code javax.swing.DefaultRowSorter#toggleSortOrder}, {@code
 * javax.swing.plaf.basic.BasicTableHeaderUI.MouseInputHandler#mouseClicked}) before writing this:
 * <b>a plain header click already does multi-column sort in stock Swing — no Shift/Ctrl gesture
 * exists anywhere in the JDK for it.</b> The stock {@code DefaultRowSorter} implementation cycles a
 * re-clicked primary column desc → ascending (never removing it); this override changes only that one
 * branch to desc → <i>removed</i>, which is the "third click clears the sort" behavior this class has
 * always provided — for a single sorted column that's unchanged from before, and for a multi-column
 * sort it now correctly drops just the primary key instead of collapsing the whole list down to one
 * column (the previous implementation's bug: it replaced the entire {@code sortKeys} list on every
 * click, discarding secondary/tertiary keys unconditionally).
 */
public final class TriStateRowSorter<M extends TableModel> extends TableRowSorter<M> {

    public TriStateRowSorter(M model) {
        super(model);
    }

    @Override
    public void toggleSortOrder(int column) {
        if (!isSortable(column)) {
            return;
        }
        List<SortKey> keys = new ArrayList<>(getSortKeys());
        int idx = -1;
        for (int i = 0; i < keys.size(); i++) {
            if (keys.get(i).getColumn() == column) {
                idx = i;
                break;
            }
        }
        if (idx == 0) {
            // Already the primary key: ascending -> descending -> removed. (Stock DefaultRowSorter
            // cycles descending -> ascending instead of removing -- that's the one line this class
            // changes; everything else below mirrors it exactly.)
            if (keys.get(0).getSortOrder() == SortOrder.ASCENDING) {
                keys.set(0, new SortKey(column, SortOrder.DESCENDING));
            } else {
                keys.remove(0);
            }
        } else {
            if (idx > 0) {
                keys.remove(idx);   // was a secondary/tertiary key -- promote to primary, ascending
            }
            keys.add(0, new SortKey(column, SortOrder.ASCENDING));
            if (keys.size() > getMaxSortKeys()) {
                keys = new ArrayList<>(keys.subList(0, getMaxSortKeys()));
            }
        }
        setSortKeys(keys);
    }

    /**
     * Wraps {@code table}'s current header renderer so a column's header shows its sort priority
     * ("2", "3", ...) whenever more than one sort key is active -- the JDK's own default header
     * renderer ({@code sun.swing.table.DefaultTableCellHeaderRenderer}, confirmed by reading its
     * source) only ever paints an ascending/descending arrow, with no indication of priority when
     * multiple columns are sorted, so a 1st and 2nd sort column would otherwise look identical. Never
     * references JDK-internal ({@code sun.swing.*}) classes: this delegates to whatever renderer the
     * table already had for 100% of the visual work (background, font, border, the arrow icon itself)
     * and only appends a numeric suffix to the label text. Call once, right after installing this
     * sorter on the table.
     */
    static void installMultiSortHeader(JTable table) {
        TableCellRenderer base = table.getTableHeader().getDefaultRenderer();
        table.getTableHeader().setDefaultRenderer((t, value, sel, focus, row, column) -> {
            Component c = base.getTableCellRendererComponent(t, value, sel, focus, row, column);
            RowSorter<?> sorter = t.getRowSorter();
            if (c instanceof JLabel label && sorter != null) {
                List<? extends SortKey> keys = sorter.getSortKeys();
                if (keys.size() > 1) {
                    int modelCol = t.convertColumnIndexToModel(column);
                    for (int i = 0; i < keys.size(); i++) {
                        if (keys.get(i).getColumn() == modelCol) {
                            label.setText(label.getText() + " " + (i + 1));
                            break;
                        }
                    }
                }
            }
            return c;
        });
    }
}
