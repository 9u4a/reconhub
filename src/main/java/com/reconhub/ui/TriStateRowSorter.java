package com.reconhub.ui;

import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import java.util.List;

/**
 * A {@link TableRowSorter} whose header clicks cycle <b>ascending → descending → unsorted</b>
 * (the model's default order) instead of only toggling asc/desc. The third click clears the sort.
 */
public final class TriStateRowSorter<M extends TableModel> extends TableRowSorter<M> {

    public TriStateRowSorter(M model) {
        super(model);
    }

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
                setSortKeys(null);   // third click: back to unsorted (default model order)
                return;
            }
        }
        setSortKeys(List.of(new RowSorter.SortKey(column, SortOrder.ASCENDING)));
    }
}
