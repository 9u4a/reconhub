package com.reconhub.ui;

import com.reconhub.analysis.PayloadCheatsheet;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import java.awt.Component;
import java.util.List;

/**
 * Shared "Payload cheatsheet" submenu for a table row's right-click menu (used by both
 * {@link ParametersPanel} and {@link FindingsPanel}). Auto-detected classes (from
 * {@link com.reconhub.analysis.ParameterClassifier}, JSON-location, value-shape heuristics, or a
 * Finding's {@code findingTypeContains} match) are offered as a one-click "Suggested" shortcut — but
 * the full class list is always browsable underneath, so a class that wasn't auto-detected (e.g. the
 * analyst suspects SQLi on a parameter the name-based classifier didn't flag) can still be picked
 * manually. Passive/reference-only — opens {@link CheatsheetDialog}, sends nothing anywhere.
 */
final class PayloadCheatsheetMenu {

    private PayloadCheatsheetMenu() {}

    /**
     * Adds a "Payload cheatsheet ▸" submenu to {@code menu}. Adds its own leading separator.
     *
     * @param suggested auto-detected sets for this row, most relevant first; empty/null if none.
     */
    static void addTo(JPopupMenu menu, Component owner, PayloadCheatsheet sheet, String context,
                      List<PayloadCheatsheet.Set> suggested) {
        if (sheet == null || sheet.allSets().isEmpty()) {
            return;
        }
        menu.addSeparator();
        JMenu top = new JMenu("Payload cheatsheet");

        if (suggested != null && !suggested.isEmpty()) {
            JMenuItem quick = new JMenuItem("Suggested (" + labelsOf(suggested) + ")");
            quick.addActionListener(e -> CheatsheetDialog.showFor(owner, context, suggested));
            top.add(quick);
            top.addSeparator();
        }

        for (PayloadCheatsheet.Set set : sheet.allSets()) {
            JMenuItem item = new JMenuItem(set.label());
            item.addActionListener(e -> CheatsheetDialog.showFor(owner, context, List.of(set)));
            top.add(item);
        }
        menu.add(top);
    }

    private static String labelsOf(List<PayloadCheatsheet.Set> sets) {
        StringBuilder sb = new StringBuilder();
        for (PayloadCheatsheet.Set s : sets) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(s.label());
        }
        return sb.toString();
    }
}
