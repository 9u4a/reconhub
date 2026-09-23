package com.reconhub.ui;

import com.reconhub.analysis.PayloadCheatsheet;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.List;

/**
 * Read-only reference dialog: one tab per applicable {@link PayloadCheatsheet.Set}, each split into a
 * "Basic" and a "Bypass / evasion" list with copy-to-clipboard actions. Purely informational — sends
 * nothing anywhere. To actually try a payload, copy it into Repeater, or mark a position and run
 * Intruder with the matching "ReconHub: &lt;class&gt;" / "ReconHub: &lt;class&gt; (bypass)" payload set
 * (registered once at load by {@code IntruderPayloads}).
 *
 * <p>Burp's Swing look-and-feel does not render {@code <html>} markup in {@code JLabel} (the tags show
 * up as literal text), so all hint/note text here uses plain, word-wrapping {@link JTextArea}s instead.
 */
public final class CheatsheetDialog extends JDialog {

    public CheatsheetDialog(Component owner, String context, List<PayloadCheatsheet.Set> sets) {
        super(ownerWindow(owner), "Payload cheatsheet — " + context, ModalityType.MODELESS);
        setLayout(new BorderLayout());

        JComponent hint = wrappedText("Reference only — nothing here is sent automatically. Copy a "
                + "payload into Repeater, or mark a position in Intruder and pick the matching "
                + "\"ReconHub: <class>\" / \"ReconHub: <class> (bypass)\" payload set.");
        hint.setBorder(BorderFactory.createEmptyBorder(8, 10, 6, 10));
        add(hint, BorderLayout.NORTH);

        JTabbedPane tabs = new JTabbedPane();
        for (PayloadCheatsheet.Set set : sets) {
            tabs.addTab(set.label(), buildTab(set));
        }
        add(tabs, BorderLayout.CENTER);

        setPreferredSize(new Dimension(520, 460));
        pack();
        setLocationRelativeTo(owner);
    }

    private JComponent buildTab(PayloadCheatsheet.Set set) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(6, 8, 8, 8));

        if (!set.note().isBlank()) {
            JComponent note = wrappedText(set.note());
            note.setAlignmentX(LEFT_ALIGNMENT);
            panel.add(note);
            panel.add(javax.swing.Box.createVerticalStrut(6));
        }

        if (!set.basic().isEmpty()) {
            panel.add(tierSection("Basic", set.basic()));
            panel.add(javax.swing.Box.createVerticalStrut(8));
        }
        if (!set.bypass().isEmpty()) {
            panel.add(tierSection("Bypass / evasion", set.bypass()));
        }
        return new JScrollPane(panel);
    }

    private JComponent tierSection(String title, List<String> payloads) {
        JPanel section = new JPanel(new BorderLayout(0, 4));
        section.setAlignmentX(LEFT_ALIGNMENT);

        JLabel heading = new JLabel(title);
        heading.setFont(heading.getFont().deriveFont(Font.BOLD, 12.5f));
        section.add(heading, BorderLayout.NORTH);

        JList<String> list = new JList<>(payloads.toArray(new String[0]));
        list.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        list.setVisibleRowCount(Math.min(payloads.size(), 8));
        JScrollPane listScroll = new JScrollPane(list);
        listScroll.setPreferredSize(new Dimension(460, Math.min(payloads.size(), 8) * 18 + 10));
        section.add(listScroll, BorderLayout.CENTER);

        JButton copySelected = new JButton("Copy selected");
        copySelected.addActionListener(e -> {
            List<String> sel = list.getSelectedValuesList();
            UiUtil.copyToClipboard(String.join("\n", sel.isEmpty() ? payloads : sel));
        });
        JButton copyAll = new JButton("Copy all");
        copyAll.addActionListener(e -> UiUtil.copyToClipboard(String.join("\n", payloads)));
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        buttons.add(copySelected);
        buttons.add(copyAll);
        section.add(buttons, BorderLayout.SOUTH);

        return section;
    }

    /**
     * A plain, word-wrapping block of text styled to look like a label. See the class Javadoc — Burp's
     * Swing environment does not render {@code <html>} in {@code JLabel}, so this is used instead.
     */
    private static JComponent wrappedText(String text) {
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setFocusable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setOpaque(false);
        area.setBorder(null);
        area.setFont(new JLabel().getFont().deriveFont(Font.ITALIC));
        return area;
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
