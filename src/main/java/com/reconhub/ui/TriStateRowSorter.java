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
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * A {@link TableRowSorter} whose header clicks cycle <b>ascending → descending → unsorted</b>.
 *
 * <p>A plain click sorts by <b>only</b> the clicked column, replacing any other active sort keys --
 * this is the default, and matches every other table in the app before 0.40.0. <b>Shift+click adds the
 * clicked column as a secondary/tertiary sort key instead</b> (kept in addition to, not instead of, the
 * existing ones, up to {@link #getMaxSortKeys()}), for a genuine multi-column sort (e.g. Host, then
 * Status within each Host) without that being the surprise default on every plain click.
 *
 * <p>0.40.0 originally made every plain click behave like Shift+click does now (mirroring {@code
 * javax.swing.DefaultRowSorter}'s own stock algorithm, which -- confirmed by reading the JDK 21 source,
 * {@code lib/src.zip} -- already does multi-column sort on a plain click with no modifier gesture
 * anywhere in Swing for it). User feedback: that was inconvenient as the unconditional default, so
 * 0.40.1 gates it behind Shift instead, via {@link #setMultiKeyDown(boolean)} -- {@link
 * #installMultiSortHeader(JTable)}'s {@code mousePressed} listener records the modifier state before
 * the header's own {@code mouseClicked} handler calls {@link #toggleSortOrder(int)} for the same click
 * (AWT dispatches all listeners' {@code mousePressed} before any {@code mouseClicked} for one
 * interaction, so this ordering is reliable regardless of listener registration order -- verified
 * against {@code javax.swing.plaf.basic.BasicTableHeaderUI.MouseInputHandler}, which has no modifier
 * check of its own and unconditionally calls {@code toggleSortOrder(columnIndex)} on click).
 */
public final class TriStateRowSorter<M extends TableModel> extends TableRowSorter<M> {

    private volatile boolean multiKeyDown;

    public TriStateRowSorter(M model) {
        super(model);
    }

    /** Set by {@link #installMultiSortHeader}'s {@code mousePressed} listener for the click about to
     * trigger {@link #toggleSortOrder}. Package-private: not meant to be driven directly. */
    void setMultiKeyDown(boolean down) {
        this.multiKeyDown = down;
    }

    @Override
    public void toggleSortOrder(int column) {
        if (!isSortable(column)) {
            return;
        }
        if (multiKeyDown) {
            multiColumnToggle(column);
        } else {
            singleColumnToggle(column);
        }
    }

    /** Default (no modifier) gesture: this column, and only this column. Cycles ascending ->
     * descending -> unsorted when re-clicking the column that's already the sole sort key; clicking any
     * other column always replaces the sort entirely, even if it was previously multi-column. */
    private void singleColumnToggle(int column) {
        List<? extends SortKey> keys = getSortKeys();
        if (keys.size() == 1 && keys.get(0).getColumn() == column) {
            if (keys.get(0).getSortOrder() == SortOrder.ASCENDING) {
                setSortKeys(List.of(new SortKey(column, SortOrder.DESCENDING)));
            } else {
                setSortKeys(null);
            }
            return;
        }
        setSortKeys(List.of(new SortKey(column, SortOrder.ASCENDING)));
    }

    /** Shift+click gesture: add/promote this column while keeping the others -- mirrors stock {@code
     * DefaultRowSorter#toggleSortOrder} exactly, except the already-primary column cycles to
     * <i>removed</i> on a third click instead of stock's cycle back to ascending. */
    private void multiColumnToggle(int column) {
        List<SortKey> keys = new ArrayList<>(getSortKeys());
        int idx = -1;
        for (int i = 0; i < keys.size(); i++) {
            if (keys.get(i).getColumn() == column) {
                idx = i;
                break;
            }
        }
        if (idx == 0) {
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
     * ("2", "3", ...) whenever more than one sort key is active (only reachable via Shift+click, see
     * the class javadoc) -- the JDK's own default header renderer ({@code
     * sun.swing.table.DefaultTableCellHeaderRenderer}, confirmed by reading its source) only ever
     * paints an ascending/descending arrow, with no indication of priority. Never references
     * JDK-internal ({@code sun.swing.*}) classes: this delegates to whatever renderer the table already
     * had for 100% of the visual work (background, font, border, the arrow icon itself) and only
     * appends a numeric suffix to the label text. Also installs the {@code mousePressed} listener that
     * feeds {@link #setMultiKeyDown}. Call once, right after installing this sorter on the table.
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
        table.getTableHeader().addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (table.getRowSorter() instanceof TriStateRowSorter<?> sorter) {
                    sorter.setMultiKeyDown(e.isShiftDown());
                }
            }
        });
    }
}
