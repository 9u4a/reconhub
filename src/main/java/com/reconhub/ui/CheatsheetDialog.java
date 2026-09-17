package com.reconhub.ui;

import com.reconhub.analysis.PayloadCheatsheet;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.ListSelectionModel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.List;

/**
 * Read-only reference dialog: one tab per applicable {@link PayloadCheatsheet.Set}, each listing its
 * payloads with a copy-to-clipboard action. Purely informational — sends nothing anywhere. To actually
 * try a payload, copy it into Repeater, or mark a position and run Intruder with the matching
 * "ReconHub: &lt;class&gt;" payload set (registered once at load by {@code IntruderPayloads}).
 */
public final class CheatsheetDialog extends JDialog {

    public CheatsheetDialog(Component owner, String context, List<PayloadCheatsheet.Set> sets) {
        super(ownerWindow(owner), "Payload cheatsheet — " + context, ModalityType.MODELESS);
        setLayout(new BorderLayout());

        JLabel hint = new JLabel("<html>Reference only — nothing here is sent automatically. Copy a "
                + "payload into Repeater, or mark a position in Intruder and pick the matching "
                + "<b>\"ReconHub: &lt;class&gt;\"</b> payload set.</html>");
        hint.setBorder(BorderFactory.createEmptyBorder(8, 10, 6, 10));
        add(hint, BorderLayout.NORTH);

        JTabbedPane tabs = new JTabbedPane();
        for (PayloadCheatsheet.Set set : sets) {
            tabs.addTab(set.label(), buildTab(set));
        }
        add(tabs, BorderLayout.CENTER);

        setPreferredSize(new Dimension(480, 360));
        pack();
        setLocationRelativeTo(owner);
    }

    private JComponent buildTab(PayloadCheatsheet.Set set) {
        JPanel panel = new JPanel(new BorderLayout());
        if (!set.note().isBlank()) {
            JLabel note = new JLabel("<html><i>" + escape(set.note()) + "</i></html>");
            note.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
            panel.add(note, BorderLayout.NORTH);
        }

        JList<String> list = new JList<>(set.payloads().toArray(new String[0]));
        list.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        panel.add(new JScrollPane(list), BorderLayout.CENTER);

        JButton copySelected = new JButton("Copy selected");
        copySelected.addActionListener(e -> {
            List<String> sel = list.getSelectedValuesList();
            copy(String.join("\n", sel.isEmpty() ? set.payloads() : sel));
        });
        JButton copyAll = new JButton("Copy all");
        copyAll.addActionListener(e -> copy(String.join("\n", set.payloads())));

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        buttons.add(copySelected);
        buttons.add(copyAll);
        panel.add(buttons, BorderLayout.SOUTH);
        return panel;
    }

    private static void copy(String s) {
        if (s != null && !s.isEmpty()) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(s), null);
        }
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static java.awt.Window ownerWindow(Component c) {
        return c == null ? null : javax.swing.SwingUtilities.getWindowAncestor(c);
    }

    /** Convenience: shows the dialog, or an info message when no cheatsheet applies. */
    public static void showFor(Component owner, String context, List<PayloadCheatsheet.Set> sets) {
        if (sets == null || sets.isEmpty()) {
            JOptionPane.showMessageDialog(owner, "No payload cheatsheet for this row.",
                    "ReconHub", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        CheatsheetDialog dlg = new CheatsheetDialog(owner, context, sets);
        dlg.setVisible(true);
    }
}
