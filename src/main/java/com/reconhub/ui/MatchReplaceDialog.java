package com.reconhub.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.reconhub.active.MatchReplaceEngine;
import com.reconhub.active.MatchReplaceJob;
import com.reconhub.active.MatchReplaceRule;
import com.reconhub.core.Settings;
import com.reconhub.model.Endpoint;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.List;

/**
 * Configuration + confirmation dialog for the Match & Replace bulk-send feature (0.42.0), opened from
 * {@code EndpointsPanel}'s "Send N selected with Match & Replace…" menu item. Shown for <b>every</b>
 * run, no "don't ask again" -- same strength as {@code RunBruteforceAction}'s confirmation, and (unlike
 * bruteforce) layered on top of the {@link Settings#isMatchReplaceEnabled()} flag rather than
 * substituting for it.
 */
final class MatchReplaceDialog {

    private static final int PREVIEW_MAX = 2000;

    private MatchReplaceDialog() {}

    static void show(Component owner, MatchReplaceEngine engine, Settings settings, List<Endpoint> targets) {
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

        JRadioButton headerMode = new JRadioButton("Header / Cookie value", true);
        JRadioButton rawMode = new JRadioButton("Raw request text");
        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(headerMode);
        modeGroup.add(rawMode);

        JTextField headerName = new JTextField("Cookie", 22);
        JCheckBox addIfMissing = new JCheckBox("Add header if missing", true);
        JTextField matchField = new JTextField(26);
        JTextField replaceField = new JTextField(26);
        JCheckBox useRegex = new JCheckBox("Use regex");

        JTextArea before = previewArea();
        JTextArea after = previewArea();
        JLabel errorLabel = new JLabel(" ");
        errorLabel.setForeground(new Color(0xc0392b));
        errorLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        Endpoint previewTarget = targets.get(0);

        Runnable updatePreview = () -> {
            MatchReplaceRule rule = buildRule(headerMode.isSelected(), headerName.getText(),
                    matchField.getText(), useRegex.isSelected(), replaceField.getText(),
                    addIfMissing.isSelected());
            String err = rule.regexError();
            errorLabel.setText(err == null ? " " : err);

            HttpRequestResponse rr = previewTarget.getMessages();
            HttpRequest req = rr == null ? null : rr.request();
            if (req == null) {
                before.setText("(no captured request to preview for " + previewTarget.getPath() + ")");
                after.setText("");
                return;
            }
            if (err != null) {
                before.setText("");
                after.setText("(fix the regex above to see a preview)");
                return;
            }
            if (rule.mode() == MatchReplaceRule.Mode.HEADER) {
                String name = rule.headerName();
                String cur = name != null && !name.isBlank() && req.hasHeader(name)
                        ? req.headerValue(name) : null;
                before.setText((name == null ? "" : name) + ": " + (cur == null ? "(not present)" : cur));
                String next = rule.computeHeaderValue(cur);
                after.setText((name == null ? "" : name) + ": " + (next == null
                        ? "(unchanged -- header absent and \"Add header if missing\" is off)" : next));
            } else {
                String rawBefore = req.toString();
                before.setText(truncate(rawBefore));
                after.setText(truncate(rule.computeRawText(rawBefore)));
            }
        };

        addLiveUpdate(headerName, updatePreview);
        addLiveUpdate(matchField, updatePreview);
        addLiveUpdate(replaceField, updatePreview);
        addIfMissing.addActionListener(e -> updatePreview.run());
        useRegex.addActionListener(e -> updatePreview.run());
        Runnable applyModeEnablement = () -> {
            boolean h = headerMode.isSelected();
            headerName.setEnabled(h);
            addIfMissing.setEnabled(h);
        };
        headerMode.addActionListener(e -> { applyModeEnablement.run(); updatePreview.run(); });
        rawMode.addActionListener(e -> { applyModeEnablement.run(); updatePreview.run(); });
        applyModeEnablement.run();
        updatePreview.run();

        JPanel root = new JPanel();
        root.setLayout(new BoxLayout(root, BoxLayout.Y_AXIS));
        root.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));

        root.add(left(new JLabel(targets.size() + " endpoint(s) selected.")));
        root.add(Box.createVerticalStrut(8));

        JPanel modeRow = row();
        modeRow.add(headerMode);
        modeRow.add(rawMode);
        root.add(modeRow);

        JPanel headerRow = row();
        headerRow.add(new JLabel("Header name:"));
        headerRow.add(headerName);
        headerRow.add(addIfMissing);
        root.add(headerRow);

        JPanel matchRow = row();
        matchRow.add(new JLabel("Match (blank = whole value/text):"));
        matchRow.add(matchField);
        root.add(matchRow);

        JPanel replaceRow = row();
        replaceRow.add(new JLabel("Replace with:"));
        replaceRow.add(replaceField);
        replaceRow.add(useRegex);
        root.add(replaceRow);
        root.add(errorLabel);

        root.add(Box.createVerticalStrut(6));
        root.add(left(new JLabel("Preview — first selected endpoint, before:")));
        root.add(scrolled(before));
        root.add(left(new JLabel("after:")));
        root.add(scrolled(after));

        root.add(Box.createVerticalStrut(8));
        root.add(left(new JLabel("Throttle: " + settings.getMatchReplaceDelayMs() + " ms delay, "
                + "concurrency " + settings.getMatchReplaceConcurrency()
                + "  (Settings → Match & Replace)")));
        root.add(left(new JLabel("Requests will be sent to " + targets.size() + " target(s). Proceed?")));

        int choice = JOptionPane.showConfirmDialog(owner, root,
                "ReconHub — confirm Match & Replace send (active)",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice != JOptionPane.OK_OPTION) {
            return;
        }

        MatchReplaceRule rule = buildRule(headerMode.isSelected(), headerName.getText(),
                matchField.getText(), useRegex.isSelected(), replaceField.getText(),
                addIfMissing.isSelected());
        String err = rule.regexError();
        if (err != null) {
            JOptionPane.showMessageDialog(owner, err, "ReconHub", JOptionPane.WARNING_MESSAGE);
            return;
        }
        MatchReplaceJob job = engine.submit(targets, rule);
        if (job == null) {
            JOptionPane.showMessageDialog(owner,
                    "Refused — Match & Replace may have been turned off, or there was nothing to send.",
                    "ReconHub", JOptionPane.WARNING_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(owner,
                    "Started against " + job.getTotal() + " endpoint(s). Track progress in the "
                            + "Match & Replace tab.",
                    "ReconHub", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private static MatchReplaceRule buildRule(boolean headerModeSelected, String headerName, String match,
                                              boolean useRegex, String replace, boolean addIfMissing) {
        return new MatchReplaceRule(
                headerModeSelected ? MatchReplaceRule.Mode.HEADER : MatchReplaceRule.Mode.RAW,
                headerModeSelected ? headerName.trim() : null,
                match, useRegex, replace, addIfMissing);
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

    private static void addLiveUpdate(JTextField field, Runnable onChange) {
        field.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { onChange.run(); }
            @Override public void removeUpdate(DocumentEvent e) { onChange.run(); }
            @Override public void changedUpdate(DocumentEvent e) { onChange.run(); }
        });
    }
}
