package com.reconhub.ui;

import org.junit.jupiter.api.Test;

import javax.swing.RowSorter.SortKey;
import javax.swing.SortOrder;
import javax.swing.table.AbstractTableModel;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code TriStateRowSorter.toggleSortOrder} -- 0.40.0's multi-column sort fix. Pure logic (a
 * {@code TableModel} is all a {@code RowSorter} needs; nothing here requires a display), verified
 * against the exact behavior {@code javax.swing.DefaultRowSorter#toggleSortOrder} has in JDK 21's own
 * source (read directly from {@code lib/src.zip} before writing this): a plain click promotes the
 * clicked column to primary and keeps prior sort columns as secondary/tertiary, up to {@code
 * getMaxSortKeys()} (default 3) -- this class only changes what happens when the *already-primary*
 * column is re-clicked a second time (removed, instead of stock's cycle back to ascending).
 */
class TriStateRowSorterTest {

    /** A trivial 5-column table model -- only column count/sortability matters for these tests. */
    private static final class FakeModel extends AbstractTableModel {
        @Override public int getRowCount() { return 0; }
        @Override public int getColumnCount() { return 5; }
        @Override public Object getValueAt(int r, int c) { return null; }
    }

    private static List<Integer> columnsOf(List<? extends SortKey> keys) {
        return keys.stream().map(SortKey::getColumn).toList();
    }

    @Test
    void firstClickOnAColumnSortsAscendingByThatColumnAlone() {
        var sorter = new TriStateRowSorter<>(new FakeModel());
        sorter.toggleSortOrder(0);
        assertEquals(List.of(0), columnsOf(sorter.getSortKeys()));
        assertEquals(SortOrder.ASCENDING, sorter.getSortKeys().get(0).getSortOrder());
    }

    @Test
    void secondClickOnTheSameColumnReversesItInPlace() {
        var sorter = new TriStateRowSorter<>(new FakeModel());
        sorter.toggleSortOrder(0);
        sorter.toggleSortOrder(0);
        assertEquals(List.of(0), columnsOf(sorter.getSortKeys()));
        assertEquals(SortOrder.DESCENDING, sorter.getSortKeys().get(0).getSortOrder());
    }

    @Test
    void thirdClickOnTheSameColumnClearsTheSortEntirely() {
        var sorter = new TriStateRowSorter<>(new FakeModel());
        sorter.toggleSortOrder(0);
        sorter.toggleSortOrder(0);
        sorter.toggleSortOrder(0);
        assertTrue(sorter.getSortKeys().isEmpty());
    }

    @Test
    void clickingADifferentColumnAddsItAsPrimaryAndKeepsThePriorAsSecondary() {
        // The core fix: this used to wipe column 0's sort entirely. Now it must survive as secondary.
        var sorter = new TriStateRowSorter<>(new FakeModel());
        sorter.toggleSortOrder(0);   // [0-asc]
        sorter.toggleSortOrder(1);   // [1-asc, 0-asc]
        assertEquals(List.of(1, 0), columnsOf(sorter.getSortKeys()));
        assertEquals(SortOrder.ASCENDING, sorter.getSortKeys().get(0).getSortOrder());
        assertEquals(SortOrder.ASCENDING, sorter.getSortKeys().get(1).getSortOrder());
    }

    @Test
    void reClickingASecondaryColumnPromotesItToPrimaryAscending() {
        var sorter = new TriStateRowSorter<>(new FakeModel());
        sorter.toggleSortOrder(0);   // [0-asc]
        sorter.toggleSortOrder(1);   // [1-asc, 0-asc]
        sorter.toggleSortOrder(0);   // re-click the now-secondary column 0 -> promoted to primary
        assertEquals(List.of(0, 1), columnsOf(sorter.getSortKeys()));
        assertEquals(SortOrder.ASCENDING, sorter.getSortKeys().get(0).getSortOrder());
        // column 1 keeps whatever order it had (still ascending, untouched by the promotion)
        assertEquals(SortOrder.ASCENDING, sorter.getSortKeys().get(1).getSortOrder());
    }

    @Test
    void clearingThePrimaryColumnLeavesTheSecondaryKeysIntact() {
        var sorter = new TriStateRowSorter<>(new FakeModel());
        sorter.toggleSortOrder(0);   // [0-asc]
        sorter.toggleSortOrder(1);   // [1-asc, 0-asc]
        sorter.toggleSortOrder(1);   // 1 is primary -> desc: [1-desc, 0-asc]
        sorter.toggleSortOrder(1);   // 1 is primary, desc -> removed: [0-asc]
        assertEquals(List.of(0), columnsOf(sorter.getSortKeys()));
    }

    @Test
    void fourthDistinctColumnEvictsTheOldestKeyAtTheDefaultMaxOfThree() {
        var sorter = new TriStateRowSorter<>(new FakeModel());
        sorter.toggleSortOrder(0);   // [0]
        sorter.toggleSortOrder(1);   // [1,0]
        sorter.toggleSortOrder(2);   // [2,1,0]
        assertEquals(3, sorter.getMaxSortKeys());
        sorter.toggleSortOrder(3);   // [3,2,1] -- column 0 falls off the end
        assertEquals(List.of(3, 2, 1), columnsOf(sorter.getSortKeys()));
    }

    @Test
    void unsortableColumnIsANoOp() {
        var sorter = new TriStateRowSorter<>(new FakeModel());
        sorter.setSortable(2, false);
        sorter.toggleSortOrder(2);
        assertTrue(sorter.getSortKeys().isEmpty());
    }
}
