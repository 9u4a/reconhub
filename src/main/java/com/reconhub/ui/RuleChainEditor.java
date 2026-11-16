package com.reconhub.ui;

import com.reconhub.active.MatchReplaceRule;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.Component;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;

/**
 * Editor for an ordered chain of extra {@link MatchReplaceRule}s (0.61.0, extracted from the 0.43 dialog).
 * Zero rows is valid (no extra rules). Each row: mode, target name, match, replacement, regex flag.
 * {@code onChange} runs (debounced for text) whenever the chain changes.
 */
final class RuleChainEditor extends JPanel {

    private static final String[] MODES = {"Header value", "Cookie value", "Remove header", "Remove cookie",
            "Raw request text"};

    private final List<Row> rows = new ArrayList<>();
    private final JPanel list = new JPanel();
    private final Runnable onChange;

    private final class Row {
        final JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        final JComboBox<String> mode = new JComboBox<>(MODES);
        final JTextField name = new JTextField("X-Header", 12);
        final JTextField match = new JTextField(14);
        final JTextField replace = new JTextField(16);
        final JCheckBox regex = new JCheckBox("regex");
        final JCheckBox addIfMissing = new JCheckBox("add if missing", true);
        final JButton remove = new JButton("✕");

        Row() {
            panel.setAlignmentX(Component.LEFT_ALIGNMENT);
            panel.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, SwingColors.line()));
            remove.setToolTipText("Remove this rule");
            match.setToolTipText("Text or regex to find (blank = the whole value)");
            panel.add(mode);
            panel.add(name);
            panel.add(new JLabel("match"));
            panel.add(match);
            panel.add(new JLabel("→"));
            panel.add(replace);
            panel.add(regex);
            panel.add(addIfMissing);
            panel.add(remove);
            mode.addActionListener(e -> { enable(); onChange.run(); });
            regex.addActionListener(e -> onChange.run());
            addIfMissing.addActionListener(e -> onChange.run());
            live(name);
            live(match);
            live(replace);
            remove.addActionListener(e -> {
                rows.remove(this);
                list.remove(panel);
                list.revalidate();
                list.repaint();
                onChange.run();
            });
            enable();
        }

        void enable() {
            int m = mode.getSelectedIndex();
            boolean raw = m == 4;
            boolean removing = m == 2 || m == 3;
            name.setEnabled(!raw);
            match.setEnabled(!removing && m != 1);
            replace.setEnabled(!removing);
            regex.setEnabled(!removing && m != 1);
            addIfMissing.setEnabled(m == 0);
        }

        MatchReplaceRule toRule() {
            String n = name.getText().trim();
            return switch (mode.getSelectedIndex()) {
                case 1 -> MatchReplaceRule.cookie(n, replace.getText());
                case 2 -> new MatchReplaceRule(MatchReplaceRule.Mode.REMOVE_HEADER, n, "", false, "", false);
                case 3 -> MatchReplaceRule.removeCookie(n);
                case 4 -> new MatchReplaceRule(MatchReplaceRule.Mode.RAW, null, match.getText(), regex.isSelected(),
                        replace.getText(), false);
                default -> new MatchReplaceRule(MatchReplaceRule.Mode.HEADER, n, match.getText(), regex.isSelected(),
                        replace.getText(), addIfMissing.isSelected());
            };
        }

        void fill(MatchReplaceRule r) {
            mode.setSelectedIndex(switch (r.mode()) {
                case COOKIE -> 1;
                case REMOVE_HEADER -> 2;
                case REMOVE_COOKIE -> 3;
                case RAW -> 4;
                default -> 0;
            });
            name.setText(r.headerName() == null ? "" : r.headerName());
            match.setText(r.matchText() == null ? "" : r.matchText());
            replace.setText(r.replacement() == null ? "" : r.replacement());
            regex.setSelected(r.useRegex());
            addIfMissing.setSelected(r.addHeaderIfMissing());
            enable();
        }
    }

    RuleChainEditor(List<MatchReplaceRule> initial, Runnable onChange) {
        this.onChange = onChange == null ? () -> { } : onChange;
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        list.setLayout(new BoxLayout(list, BoxLayout.Y_AXIS));
        list.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(list);
        JButton add = new JButton("+ Add rule");
        add.setAlignmentX(Component.LEFT_ALIGNMENT);
        add.addActionListener(e -> {
            addRow(null);
            this.onChange.run();
        });
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        bar.setAlignmentX(Component.LEFT_ALIGNMENT);
        bar.add(add);
        JLabel hint = new JLabel("Applied after the session's own credentials, to every selected session.");
        hint.setForeground(SwingColors.MUTED);
        bar.add(hint);
        add(bar);
        if (initial != null) for (MatchReplaceRule r : initial) addRow(r);
    }

    private void addRow(MatchReplaceRule r) {
        Row row = new Row();
        if (r != null) row.fill(r);
        rows.add(row);
        list.add(row.panel);
        list.revalidate();
        list.repaint();
    }

    List<MatchReplaceRule> rules() {
        List<MatchReplaceRule> out = new ArrayList<>();
        for (Row r : rows) out.add(r.toRule());
        return out;
    }

    int ruleCount() {
        return rows.size();
    }

    /** First regex compile error in the chain, or null. */
    String error() {
        for (MatchReplaceRule r : rules()) {
            String e = r.regexError();
            if (e != null) return e;
        }
        return null;
    }

    private void live(JTextField f) {
        Timer t = new Timer(200, e -> onChange.run());
        t.setRepeats(false);
        f.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { t.restart(); }
            @Override public void removeUpdate(DocumentEvent e) { t.restart(); }
            @Override public void changedUpdate(DocumentEvent e) { t.restart(); }
        });
    }
}
