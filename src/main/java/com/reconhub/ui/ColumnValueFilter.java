package com.reconhub.ui;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;

/**
 * A Burp-History-filter-style "pick which values of this column to show" quick filter: a small button
 * that opens a checklist of every distinct value currently present in the column, letting the user
 * uncheck the ones to hide. An empty exclusion set means "no filtering" -- the widget can never default
 * to (or silently end up) hiding everything.
 *
 * <p><b>Uses plain {@link JCheckBox}es added directly to a {@link JPopupMenu}, not {@link
 * javax.swing.JCheckBoxMenuItem}.</b> A {@code JCheckBoxMenuItem} is a {@code MenuElement}, and
 * clicking one closes the enclosing popup immediately (standard Swing menu behavior) -- which would
 * only let the user toggle one value per click of the filter button, defeating the entire point of a
 * multi-select checklist. A plain {@code JComponent} added to a {@code JPopupMenu} is not a {@code
 * MenuElement}, so clicking it does not auto-close the popup -- confirmed by construction (this is a
 * well-known, deliberate Swing technique, not an accident of this specific L&amp;F).
 */
final class ColumnValueFilter<T> {

    private final String label;
    private final Function<T, String> valueOf;
    private final JButton button = new JButton();
    private final Set<String> excluded = new HashSet<>();   // empty = no filter (show everything)
    private Set<String> available = Set.of();
    private Runnable onChange = () -> {};

    ColumnValueFilter(String label, Function<T, String> valueOf) {
        this.label = label;
        this.valueOf = valueOf;
        button.addActionListener(e -> showPopup());
        updateLabel();
    }

    JButton component() {
        return button;
    }

    /** Called whenever a checkbox is toggled (and after "Select all"/"Select none") -- wire to the
     * panel's {@code reapplyFilter()}. */
    void setOnChange(Runnable r) {
        this.onChange = r;
    }

    /** Package-private for headless testing (see {@code ColumnValueFilterTest}) -- runs exactly the
     * same mutation + label-update + onChange sequence the popup's checkbox listener does, without
     * needing to drive the actual popup UI. */
    void setValueShown(String value, boolean shown) {
        if (shown) {
            excluded.remove(value);
        } else {
            excluded.add(value);
        }
        updateLabel();
        onChange.run();
    }

    /** @return true when {@code row} should be shown under the current selection. */
    boolean test(T row) {
        if (excluded.isEmpty()) {
            return true;
        }
        String v = valueOf.apply(row);
        return v == null || !excluded.contains(v);
    }

    /**
     * Refreshes the set of values the checklist offers, from the current row list -- call after every
     * data refresh (the same place a panel already re-derives other live UI state, e.g. {@code
     * FindingsPanel.refreshData()}'s category-combo rebuild). A value that no longer appears in the
     * data is also dropped from {@link #excluded}, so a stale filter can't keep hiding rows forever
     * after the data that justified it is gone.
     */
    void refreshAvailableValues(List<T> rows) {
        Set<String> present = new TreeSet<>();
        for (T row : rows) {
            String v = valueOf.apply(row);
            if (v != null && !v.isEmpty()) {
                present.add(v);
            }
        }
        excluded.retainAll(present);
        available = present;
        updateLabel();
    }

    private void showPopup() {
        JPopupMenu popup = new JPopupMenu();
        JPanel list = new JPanel();
        list.setLayout(new BoxLayout(list, BoxLayout.Y_AXIS));
        for (String value : available) {
            JCheckBox cb = new JCheckBox(value, !excluded.contains(value));
            cb.addActionListener(e -> setValueShown(value, cb.isSelected()));
            list.add(cb);
        }
        popup.add(list);
        popup.addSeparator();
        // Plain JMenuItems here (not JCheckBoxes) -- these are one-shot bulk actions, not something
        // the user needs to combine with more toggling in the same popup session, so the standard
        // close-on-click menu behavior is fine (and expected).
        JMenuItem selectAll = new JMenuItem("Select all");
        selectAll.addActionListener(e -> {
            excluded.clear();
            updateLabel();
            onChange.run();
        });
        popup.add(selectAll);
        JMenuItem selectNone = new JMenuItem("Select none");
        selectNone.addActionListener(e -> {
            excluded.addAll(available);
            updateLabel();
            onChange.run();
        });
        popup.add(selectNone);
        popup.show(button, 0, button.getHeight());
    }

    private void updateLabel() {
        button.setText(excluded.isEmpty()
                ? label + " ▾"
                : label + " (" + (available.size() - excluded.size()) + "/" + available.size() + ") ▾");
    }
}
