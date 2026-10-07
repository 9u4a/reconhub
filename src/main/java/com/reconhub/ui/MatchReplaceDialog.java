package com.reconhub.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.reconhub.active.MatchReplaceEngine;
import com.reconhub.active.MatchReplaceJob;
import com.reconhub.active.MatchReplaceRule;
import com.reconhub.active.MatchReplaceTarget;
import com.reconhub.core.Settings;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration + confirmation dialog for the Match & Replace bulk-send feature, opened from any
 * source panel's "Send N selected with Match & Replace…" menu item (Endpoints/Parameters/Findings/JS
 * Assets, 0.43.0). Shown for <b>every</b> run, no "don't ask again" -- same strength as {@code
 * RunBruteforceAction}'s confirmation, and (unlike bruteforce) layered on top of the {@link
 * Settings#isMatchReplaceEnabled()} flag rather than substituting for it.
 *
 * <p><b>Rule chaining (0.43.0)</b>: one or more rule rows, applied in order. The live preview reuses
 * {@link MatchReplaceEngine#buildRequest} -- the exact code path that actually sends -- against the
 * first selected target's real captured request, rather than a hand-rolled approximation, so what's
 * shown is guaranteed to match what would actually go out.
 */
final class MatchReplaceDialog {

    private static final int PREVIEW_MAX = 2000;

    private MatchReplaceDialog() {}

    /** One rule's input row -- bundles the Swing components so the dialog can read back a {@link
     * MatchReplaceRule} from whatever the user currently has entered. */
    private static final class RuleRow {
        final JPanel panel = new JPanel();
        final JRadioButton headerMode = new JRadioButton("Header / Cookie value", true);
        final JRadioButton rawMode = new JRadioButton("Raw request text");
        final JTextField headerName = new JTextField("Cookie", 18);
        final JCheckBox addIfMissing = new JCheckBox("Add header if missing", true);
        final JTextField matchField = new JTextField(22);
        final JTextField replaceField = new JTextField(22);
        final JCheckBox useRegex = new JCheckBox("Use regex");
        final JButton remove = new JButton("Remove");

        MatchReplaceRule toRule() {
            boolean h = headerMode.isSelected();
            return new MatchReplaceRule(
                    h ? MatchReplaceRule.Mode.HEADER : MatchReplaceRule.Mode.RAW,
                    h ? headerName.getText().trim() : null,
                    matchField.getText(), useRegex.isSelected(), replaceField.getText(),
                    addIfMissing.isSelected());
        }
    }

    static void show(Component owner, MatchReplaceEngine engine, Settings settings,
                     List<MatchReplaceTarget> targets) {
        if (targets == null || targets.isEmpty()) {
            return;
        }
        if (!settings.isMatchReplaceEnabled()) {
            JOptionPane.showMessageDialog(owner,
                    "Match & Replace is off by default (workspace target-load-safety policy — every "
                            + "ACTIVE feature here defaults to off).\n\n"
                            + "Turn it on in Settings → Match & Replace first, then try again.",
                    "ReconHub — Match & Replace is disabled", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        MatchReplaceTarget previewTarget = targets.get(0);
        List<RuleRow> ruleRows = new ArrayList<>();
        JPanel rulesContainer = new JPanel();
        rulesContainer.setLayout(new BoxLayout(rulesContainer, BoxLayout.Y_AXIS));
        rulesContainer.setAlignmentX(Component.LEFT_ALIGNMENT);

        JTextArea before = previewArea();
        JTextArea after = previewArea();
        JLabel errorLabel = new JLabel(" ");
        errorLabel.setForeground(new Color(0xc0392b));
        errorLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Computed once (0.43.8), not on every updatePreview() call -- the "before" text depends only
        // on previewTarget, fixed for the dialog's whole lifetime, unlike "after" below (which depends
        // on the current rules and so does need to be recomputed as the user edits them).
        HttpRequestResponse previewRr = previewTarget.messages();
        HttpRequest previewReq = previewRr == null ? null : previewRr.request();
        before.setText(previewReq == null
                ? "(no captured request to preview for " + previewTarget.path() + ")"
                : truncate(previewReq.toString()));

        Runnable updatePreview = () -> {
            List<MatchReplaceRule> rules = new ArrayList<>();
            String err = null;
            for (RuleRow row : ruleRows) {
                MatchReplaceRule rule = row.toRule();
                rules.add(rule);
                if (err == null) {
                    err = rule.regexError();
                }
            }
            errorLabel.setText(err == null ? " " : err);

            if (previewReq == null) {
                after.setText("");
                return;
            }
            if (err != null) {
                after.setText("(fix the regex above to see a preview)");
                return;
            }
            HttpRequest result = MatchReplaceEngine.buildRequest(previewReq, rules);
            after.setText(result == null
                    ? "(a rule in the chain doesn't apply to this request -- header not present, and "
                            + "\"Add header if missing\" is off)"
                    : truncate(result.toString()));
        };

        JButton addRule = new JButton("+ Add another rule");
        addRule.setAlignmentX(Component.LEFT_ALIGNMENT);
        addRule.addActionListener(e -> {
            RuleRow row = newRuleRow(ruleRows, rulesContainer, updatePreview);
            ruleRows.add(row);
            rulesContainer.add(row.panel);
            rulesContainer.revalidate();
            updatePreview.run();
        });

        // Start with exactly one rule row -- always at least one; "Remove" on a row is a no-op once
        // only one is left (see newRuleRow), so the chain can never become empty.
        RuleRow first = newRuleRow(ruleRows, rulesContainer, updatePreview);
        ruleRows.add(first);
        rulesContainer.add(first.panel);
        updatePreview.run();

        JPanel root = new JPanel();
        root.setLayout(new BoxLayout(root, BoxLayout.Y_AXIS));
        root.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));

        root.add(left(new JLabel(targets.size() + " row(s) selected.")));
        root.add(Box.createVerticalStrut(8));
        root.add(rulesContainer);
        root.add(addRule);
        root.add(errorLabel);

        root.add(Box.createVerticalStrut(6));
        root.add(left(new JLabel("Preview — first selected row, all rules applied, before:")));
        root.add(scrolled(before));
        root.add(left(new JLabel("after:")));
        root.add(scrolled(after));

        root.add(Box.createVerticalStrut(8));
        root.add(left(new JLabel("Throttle: " + settings.getMatchReplaceDelayMs() + " ms delay, "
                + "concurrency " + settings.getMatchReplaceConcurrency()
                + "  (Settings → Match & Replace)")));
        root.add(left(new JLabel("Requests will be sent to " + targets.size() + " target(s). Proceed?")));

        JScrollPane rootScroll = new JScrollPane(root);
        rootScroll.setBorder(null);
        rootScroll.setPreferredSize(new Dimension(640, 560));

        int choice = JOptionPane.showConfirmDialog(owner, rootScroll,
                "ReconHub — confirm Match & Replace send (active)",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice != JOptionPane.OK_OPTION) {
            return;
        }

        List<MatchReplaceRule> rules = new ArrayList<>();
        for (RuleRow row : ruleRows) {
            MatchReplaceRule rule = row.toRule();
            String err = rule.regexError();
            if (err != null) {
                JOptionPane.showMessageDialog(owner, err, "ReconHub", JOptionPane.WARNING_MESSAGE);
                return;
            }
            rules.add(rule);
        }
        MatchReplaceJob job = engine.submit(targets, rules);
        if (job == null) {
            JOptionPane.showMessageDialog(owner,
                    "Refused — Match & Replace may have been turned off, or there was nothing to send.",
                    "ReconHub", JOptionPane.WARNING_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(owner,
                    "Started against " + job.getTotal() + " target(s). Track progress in the "
                            + "Match & Replace tab.",
                    "ReconHub", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /** Builds one rule row wired for live preview + self-removal ("Remove" is a no-op once {@code
     * ruleRows} would drop to zero, checked at click time -- so the chain can never become empty). */
    private static RuleRow newRuleRow(List<RuleRow> ruleRows, JPanel rulesContainer, Runnable updatePreview) {
        RuleRow row = new RuleRow();
        JPanel p = row.panel;
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0x3a3f4b)),
                BorderFactory.createEmptyBorder(6, 8, 6, 8)));

        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(row.headerMode);
        modeGroup.add(row.rawMode);

        JPanel top = row();
        top.add(row.headerMode);
        top.add(row.rawMode);
        top.add(Box.createHorizontalStrut(20));
        top.add(row.remove);
        p.add(top);

        JPanel headerRow = row();
        headerRow.add(new JLabel("Header name:"));
        headerRow.add(row.headerName);
        headerRow.add(row.addIfMissing);
        p.add(headerRow);

        JPanel matchRow = row();
        matchRow.add(new JLabel("Match (blank = whole value/text):"));
        matchRow.add(row.matchField);
        p.add(matchRow);

        JPanel replaceRow = row();
        replaceRow.add(new JLabel("Replace with:"));
        replaceRow.add(row.replaceField);
        replaceRow.add(row.useRegex);
        p.add(replaceRow);

        addLiveUpdate(row.headerName, updatePreview);
        addLiveUpdate(row.matchField, updatePreview);
        addLiveUpdate(row.replaceField, updatePreview);
        row.addIfMissing.addActionListener(e -> updatePreview.run());
        row.useRegex.addActionListener(e -> updatePreview.run());
        Runnable applyModeEnablement = () -> {
            boolean h = row.headerMode.isSelected();
            row.headerName.setEnabled(h);
            row.addIfMissing.setEnabled(h);
        };
        row.headerMode.addActionListener(e -> { applyModeEnablement.run(); updatePreview.run(); });
        row.rawMode.addActionListener(e -> { applyModeEnablement.run(); updatePreview.run(); });
        applyModeEnablement.run();

        row.remove.addActionListener(e -> {
            if (ruleRows.size() <= 1) {
                return;   // always keep at least one rule row
            }
            ruleRows.remove(row);
            rulesContainer.remove(row.panel);
            rulesContainer.revalidate();
            rulesContainer.repaint();
            updatePreview.run();
        });

        return row;
    }

    private static String truncate(String s) {
        if (s == null) {
            return "";
        }
        return s.length() > PREVIEW_MAX ? s.substring(0, PREVIEW_MAX) + "\n…(truncated)" : s;
    }

    private static JTextArea previewArea() {
        JTextArea a = new JTextArea(6, 56);
        a.setEditable(false);
        a.setLineWrap(true);
        a.setWrapStyleWord(false);
        a.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 11));
        return a;
    }

    private static JScrollPane scrolled(JTextArea area) {
        JScrollPane sp = new JScrollPane(area);
        sp.setAlignmentX(Component.LEFT_ALIGNMENT);
        sp.setPreferredSize(new Dimension(560, 100));
        return sp;
    }

    private static JPanel row() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        return p;
    }

    private static Component left(Component c) {
        if (c instanceof JComponent jc) {
            jc.setAlignmentX(Component.LEFT_ALIGNMENT);
        }
        return c;
    }

    /** Debounced (0.43.8) -- typing in a match/replace/header-name field used to recompute the whole
     * preview (recompile+reapply every rule in the chain) synchronously on every keystroke, with no
     * debounce at all, unlike every other search/filter field in this codebase. 200ms matches {@code
     * AbstractTablePanel.debounce}'s own interval. */
    private static void addLiveUpdate(JTextField field, Runnable onChange) {
        Timer debounce = new Timer(200, e -> onChange.run());
        debounce.setRepeats(false);
        field.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { debounce.restart(); }
            @Override public void removeUpdate(DocumentEvent e) { debounce.restart(); }
            @Override public void changedUpdate(DocumentEvent e) { debounce.restart(); }
        });
    }
}
