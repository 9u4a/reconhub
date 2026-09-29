package com.reconhub.ui;

import org.junit.jupiter.api.Test;

import javax.swing.RowSorter.SortKey;
import javax.swing.SortOrder;
import javax.swing.table.AbstractTableModel;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code TriStateRowSorter.toggleSortOrder} -- 0.40.1's default-single/Shift-multi split. A plain
 * click (the default, {@code multiKeyDown == false}) sorts by only the clicked column, replacing any
 * other active keys -- 0.40.0 originally made every plain click do multi-column sort unconditionally
 * (mirroring stock {@code DefaultRowSorter}'s own JDK behavior), but that was reported as inconvenient
 * as the default, so it's now opt-in via {@code setMultiKeyDown(true)} (wired to Shift+click by {@code
 * installMultiSortHeader}, not exercised here -- these tests drive the flag directly). Pure logic (a
 * {@code TableModel} is all a {@code RowSorter} needs; nothing here requires a display).
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

    // ---- default (plain click) -- single column only -----------------------------------------------

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
    void plainClickOnADifferentColumnReplacesTheSortEntirely() {
        // The whole point of 0.40.1: without the modifier, a new column's click wipes any other key.
        var sorter = new TriStateRowSorter<>(new FakeModel());
        sorter.toggleSortOrder(0);
        sorter.toggleSortOrder(1);
        assertEquals(List.of(1), columnsOf(sorter.getSortKeys()));
    }

    @Test
    void plainClickAfterAMultiColumnSortCollapsesBackToOneColumn() {
        var sorter = new TriStateRowSorter<>(new FakeModel());
        sorter.setMultiKeyDown(true);
        sorter.toggleSortOrder(0);
        sorter.toggleSortOrder(1);   // [1,0] via the multi-key path
        assertEquals(2, sorter.getSortKeys().size());

        sorter.setMultiKeyDown(false);
        sorter.toggleSortOrder(2);   // plain click -- must discard both prior keys
        assertEquals(List.of(2), columnsOf(sorter.getSortKeys()));
    }

    @Test
    void unsortableColumnIsANoOpRegardlessOfModifier() {
        var sorter = new TriStateRowSorter<>(new FakeModel());
        sorter.setSortable(2, false);
        sorter.toggleSortOrder(2);
        assertTrue(sorter.getSortKeys().isEmpty());

        sorter.setMultiKeyDown(true);
        sorter.toggleSortOrder(2);
        assertTrue(sorter.getSortKeys().isEmpty());
    }

    // ---- Shift+click (multiKeyDown) -- genuine multi-column sort ------------------------------------

    @Test
    void multiKeyClickOnADifferentColumnAddsItAsPrimaryAndKeepsThePriorAsSecondary() {
        var sorter = new TriStateRowSorter<>(new FakeModel());
        sorter.setMultiKeyDown(true);
        sorter.toggleSortOrder(0);   // [0-asc]
        sorter.toggleSortOrder(1);   // [1-asc, 0-asc]
        assertEquals(List.of(1, 0), columnsOf(sorter.getSortKeys()));
        assertEquals(SortOrder.ASCENDING, sorter.getSortKeys().get(0).getSortOrder());
        assertEquals(SortOrder.ASCENDING, sorter.getSortKeys().get(1).getSortOrder());
    }

    @Test
    void multiKeyReClickingASecondaryColumnPromotesItToPrimaryAscending() {
        var sorter = new TriStateRowSorter<>(new FakeModel());
        sorter.setMultiKeyDown(true);
        sorter.toggleSortOrder(0);   // [0-asc]
        sorter.toggleSortOrder(1);   // [1-asc, 0-asc]
        sorter.toggleSortOrder(0);   // re-click the now-secondary column 0 -> promoted to primary
        assertEquals(List.of(0, 1), columnsOf(sorter.getSortKeys()));
        assertEquals(SortOrder.ASCENDING, sorter.getSortKeys().get(0).getSortOrder());
        assertEquals(SortOrder.ASCENDING, sorter.getSortKeys().get(1).getSortOrder());
    }

    @Test
    void multiKeyClearingThePrimaryColumnLeavesTheSecondaryKeysIntact() {
        var sorter = new TriStateRowSorter<>(new FakeModel());
        sorter.setMultiKeyDown(true);
        sorter.toggleSortOrder(0);   // [0-asc]
        sorter.toggleSortOrder(1);   // [1-asc, 0-asc]
        sorter.toggleSortOrder(1);   // 1 is primary -> desc: [1-desc, 0-asc]
        sorter.toggleSortOrder(1);   // 1 is primary, desc -> removed: [0-asc]
        assertEquals(List.of(0), columnsOf(sorter.getSortKeys()));
    }

    @Test
    void multiKeyFourthDistinctColumnEvictsTheOldestKeyAtTheDefaultMaxOfThree() {
        var sorter = new TriStateRowSorter<>(new FakeModel());
        sorter.setMultiKeyDown(true);
        sorter.toggleSortOrder(0);   // [0]
        sorter.toggleSortOrder(1);   // [1,0]
        sorter.toggleSortOrder(2);   // [2,1,0]
        assertEquals(3, sorter.getMaxSortKeys());
        sorter.toggleSortOrder(3);   // [3,2,1] -- column 0 falls off the end
        assertEquals(List.of(3, 2, 1), columnsOf(sorter.getSortKeys()));
    }
}
