package com.reconhub.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.reconhub.active.AuthDetector;
import com.reconhub.active.MatchReplaceEngine;
import com.reconhub.active.MatchReplaceJob;
import com.reconhub.active.MatchReplaceRule;
import com.reconhub.active.MatchReplaceTarget;
import com.reconhub.active.RunIdentity;
import com.reconhub.active.SessionProfiles;
import com.reconhub.core.Settings;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTextPane;
import javax.swing.JToggleButton;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.Window;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Match &amp; Replace run dialog (0.61.0 redesign; opened from any table's "Send N selected with Match &amp;
 * Replace…"). The main input is a <b>session checklist</b> -- every target is sent once per ticked session
 * (Original / No auth / saved identities); extra rules are optional and folded away. A live side-by-side
 * preview (any target × any ticked session, changed lines highlighted) uses
 * {@link MatchReplaceEngine#buildRequest} -- the exact code path that sends. Pre-checks (out of scope,
 * rules that don't apply, expired tokens) and the request count / minimum duration are shown before
 * sending. Shown for every run; the send button names the request count and "ACTIVE". On send the dialog
 * closes and the results tab opens on the new run.
 */
final class MatchReplaceDialog {

    private static final int PREVIEW_MAX = 20_000;
    private static final int PRECHECK_MAX = 300;          // targets inspected for "rule doesn't apply"
    /** Ticked sessions and extra rules remembered for the session (memory only). */
    private static Set<String> lastSessions;
    private static List<MatchReplaceRule> lastExtraRules = List.of();
    /** Set by MainTab: opens the results tab on a newly submitted run. */
    private static volatile Consumer<MatchReplaceJob> onSubmitted = j -> { };

    private MatchReplaceDialog() {}

    static void setOnSubmitted(Consumer<MatchReplaceJob> c) {
        onSubmitted = c == null ? j -> { } : c;
    }

    static void show(Component owner, MatchReplaceEngine engine, Settings settings, List<MatchReplaceTarget> targets) {
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
        new View(owner, engine, settings, targets).open();
    }

    /** Pure: identities to send as, from ticked names + extra rules. Unknown names are skipped. */
    static List<RunIdentity> identities(List<String> ticked, SessionProfiles sessions, List<MatchReplaceRule> extra) {
        List<RunIdentity> out = new ArrayList<>();
        for (String name : ticked) {
            List<MatchReplaceRule> base = sessions.rulesForName(name);
            if (base == null) continue;
            List<MatchReplaceRule> all = new ArrayList<>(base);
            all.addAll(extra);
            out.add(new RunIdentity(name, all));
        }
        return out;
    }

    private static final class View {
        final Component owner;
        final MatchReplaceEngine engine;
        final Settings settings;
        final List<MatchReplaceTarget> targets;
        final SessionProfiles sessions;
        final Map<String, JCheckBox> boxes = new LinkedHashMap<>();
        final JPanel sessionList = new JPanel();
        final JComboBox<String> targetBox = new JComboBox<>();
        final JComboBox<String> sessionBox = new JComboBox<>();
        final JTextPane before = pane();
        final JTextPane after = pane();
        final JLabel diffInfo = new JLabel(" ");
        final JLabel precheck = new JLabel(" ");
        final JLabel summary = new JLabel(" ");
        final JLabel error = new JLabel(" ");
        final JSpinner delay;
        final JSpinner conc;
        final JButton send = new JButton();
        final RuleChainEditor extra;
        final JToggleButton extraToggle = new JToggleButton();
        JDialog dialog;
        boolean refreshing;

        View(Component owner, MatchReplaceEngine engine, Settings settings, List<MatchReplaceTarget> targets) {
            this.owner = owner;
            this.engine = engine;
            this.settings = settings;
            this.targets = targets;
            this.sessions = engine.sessions();
            this.delay = new JSpinner(new SpinnerNumberModel(settings.getMatchReplaceDelayMs(), 0, 60_000, 100));
            this.conc = new JSpinner(new SpinnerNumberModel(settings.getMatchReplaceConcurrency(), 1, 10, 1));
            this.extra = new RuleChainEditor(lastExtraRules, this::refresh);
        }

        void open() {
            Window w = owner instanceof Window win ? win : owner == null ? null : SwingUtilities.getWindowAncestor(owner);
            dialog = new JDialog(w, "ReconHub — Match & Replace (ACTIVE)", java.awt.Dialog.ModalityType.MODELESS);

            // ---- header: targets ----
            JLabel targetsLabel = new JLabel(targets.size() + (targets.size() == 1 ? " target" : " targets") + " selected");
            targetsLabel.setFont(targetsLabel.getFont().deriveFont(Font.BOLD));
            DefaultListModel<String> tm = new DefaultListModel<>();
            for (MatchReplaceTarget t : targets) tm.addElement(label(t));
            JScrollPane targetScroll = new JScrollPane(new JList<>(tm));
            targetScroll.setPreferredSize(new Dimension(600, 90));
            targetScroll.setVisible(false);
            JToggleButton showTargets = new JToggleButton("Show list");
            showTargets.addActionListener(e -> {
                targetScroll.setVisible(showTargets.isSelected());
                dialog.revalidate();
            });
            JPanel header = new JPanel(new BorderLayout());
            JPanel headerRow = flow();
            headerRow.add(targetsLabel);
            headerRow.add(showTargets);
            header.add(headerRow, BorderLayout.NORTH);
            header.add(targetScroll, BorderLayout.CENTER);

            // ---- left: session checklist ----
            sessionList.setLayout(new BoxLayout(sessionList, BoxLayout.Y_AXIS));
            JButton newSession = new JButton("+ New session…");
            newSession.addActionListener(e -> SessionEditorDialog.open(dialog, sessions, null, null, "manual"));
            JPanel left = new JPanel(new BorderLayout());
            left.setBorder(BorderFactory.createTitledBorder("Send as (tick one or more)"));
            left.add(new JScrollPane(sessionList), BorderLayout.CENTER);
            JPanel leftButtons = flow();
            leftButtons.add(newSession);
            left.add(leftButtons, BorderLayout.SOUTH);
            left.setPreferredSize(new Dimension(250, 260));
            Runnable sessionListener = () -> SwingUtilities.invokeLater(() -> {
                if (dialog.isDisplayable()) {
                    rebuildSessions();
                    refresh();
                }
            });
            sessions.addListener(sessionListener);
            rebuildSessions();

            // ---- right: preview ----
            for (MatchReplaceTarget t : targets) targetBox.addItem(label(t));
            targetBox.addActionListener(e -> { if (!refreshing) updatePreview(); });
            sessionBox.addActionListener(e -> { if (!refreshing) updatePreview(); });
            JPanel previewTop = flow();
            previewTop.add(new JLabel("Preview:"));
            previewTop.add(targetBox);
            previewTop.add(new JLabel("as"));
            previewTop.add(sessionBox);
            previewTop.add(diffInfo);
            JPanel panes = new JPanel(new GridLayout(1, 2, 6, 0));
            panes.add(titled("Before (captured)", before));
            panes.add(titled("After (what will be sent)", after));
            JPanel right = new JPanel(new BorderLayout());
            right.add(previewTop, BorderLayout.NORTH);
            right.add(panes, BorderLayout.CENTER);

            JSplitPane middle = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, right);
            middle.setResizeWeight(0.0);
            middle.setDividerLocation(260);

            // ---- extra rules (folded) ----
            JScrollPane extraScroll = new JScrollPane(extra);
            extraScroll.setPreferredSize(new Dimension(800, 110));
            extraScroll.setVisible(extra.ruleCount() > 0);
            extraToggle.setSelected(extra.ruleCount() > 0);
            extraToggle.addActionListener(e -> {
                extraScroll.setVisible(extraToggle.isSelected());
                refresh();
                dialog.revalidate();
            });

            // ---- footer: throttle, pre-check, summary, buttons ----
            delay.addChangeListener(e -> refresh());
            conc.addChangeListener(e -> refresh());
            JPanel throttle = flow();
            throttle.add(new JLabel("Delay"));
            throttle.add(delay);
            throttle.add(new JLabel("ms   Concurrency"));
            throttle.add(conc);
            throttle.add(Box.createHorizontalStrut(12));
            throttle.add(precheck);
            error.setForeground(SwingColors.HIGH);
            summary.setFont(summary.getFont().deriveFont(Font.BOLD));
            JButton cancel = new JButton("Cancel");
            cancel.addActionListener(e -> dialog.dispose());
            send.setFont(send.getFont().deriveFont(Font.BOLD));
            send.addActionListener(e -> submit());
            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            buttons.add(cancel);
            buttons.add(send);
            JPanel footer = new JPanel();
            footer.setLayout(new BoxLayout(footer, BoxLayout.Y_AXIS));
            JPanel extraRow = flow();
            extraRow.add(extraToggle);
            footer.add(extraRow);
            footer.add(extraScroll);
            footer.add(throttle);
            JPanel sumRow = flow();
            sumRow.add(summary);
            sumRow.add(error);
            footer.add(sumRow);
            footer.add(buttons);

            JPanel root = new JPanel(new BorderLayout(0, 6));
            root.setBorder(BorderFactory.createEmptyBorder(8, 10, 6, 10));
            root.add(header, BorderLayout.NORTH);
            root.add(middle, BorderLayout.CENTER);
            root.add(footer, BorderLayout.SOUTH);
            dialog.setContentPane(root);
            dialog.addWindowListener(new java.awt.event.WindowAdapter() {
                @Override public void windowClosed(java.awt.event.WindowEvent e) {
                    lastExtraRules = extra.rules();
                    sessions.removeListener(sessionListener);
                }
            });
            refresh();
            dialog.setSize(1000, 680);
            dialog.setLocationRelativeTo(w);
            dialog.setVisible(true);
        }

        void rebuildSessions() {
            Set<String> ticked = new LinkedHashSet<>();
            if (boxes.isEmpty()) {
                if (lastSessions != null) {
                    ticked.addAll(lastSessions);
                } else {
                    ticked.add(SessionProfiles.ORIGINAL);
                    ticked.add(SessionProfiles.NO_AUTH);
                    for (SessionProfiles.Identity id : sessions.list()) ticked.add(id.name());
                }
            } else {
                boxes.forEach((n, b) -> { if (b.isSelected()) ticked.add(n); });
                for (SessionProfiles.Identity id : sessions.list()) {
                    if (!boxes.containsKey(id.name())) ticked.add(id.name());   // a session just added: tick it
                }
            }
            boxes.clear();
            sessionList.removeAll();
            List<String> names = new ArrayList<>(List.of(SessionProfiles.ORIGINAL, SessionProfiles.NO_AUTH));
            for (SessionProfiles.Identity id : sessions.list()) names.add(id.name());
            long now = java.time.Instant.now().getEpochSecond();
            for (String n : names) {
                SessionProfiles.Identity id = sessions.get(n);
                AuthDetector.TokenInfo ti = id == null ? null : id.tokenInfo();
                boolean expired = ti != null && ti.expired(now);
                String text = n.equals(SessionProfiles.ORIGINAL) ? "Original (baseline)"
                        : n.equals(SessionProfiles.NO_AUTH) ? "No auth" : n + (expired ? "  ⚠ expired" : "");
                JCheckBox b = new JCheckBox(text, ticked.contains(n));
                b.setToolTipText(id == null ? (n.equals(SessionProfiles.ORIGINAL)
                        ? "The request exactly as captured -- a fresh baseline to compare the others with"
                        : "Every cookie and auth header removed") : id.summary());
                if (expired) b.setForeground(SwingColors.HIGH);
                b.addActionListener(e -> refresh());
                boxes.put(n, b);
                sessionList.add(b);
            }
            sessionList.revalidate();
            sessionList.repaint();
        }

        List<String> ticked() {
            List<String> out = new ArrayList<>();
            boxes.forEach((n, b) -> { if (b.isSelected()) out.add(n); });
            return out;
        }

        /** Recomputes everything derived from the current inputs. */
        void refresh() {
            refreshing = true;
            List<String> ticked = ticked();
            try {
                Object sel = sessionBox.getSelectedItem();
                sessionBox.removeAllItems();
                for (String n : ticked) sessionBox.addItem(n);
                if (sel != null && ticked.contains(sel)) {
                    sessionBox.setSelectedItem(sel);
                } else if (ticked.size() > 1 && ticked.get(0).equals(SessionProfiles.ORIGINAL)) {
                    sessionBox.setSelectedIndex(1);   // previewing Original shows no change -- start on the next
                }
            } finally {
                refreshing = false;
            }

            extraToggle.setText((extraToggle.isSelected() ? "▾" : "▸") + " Extra rules (advanced): " + extra.ruleCount());
            String err = extra.error();
            error.setText(err == null ? " " : "  " + err);

            int outOfScope = 0;
            int noApply = 0;
            List<RunIdentity> ids = identities(ticked, sessions, err == null ? extra.rules() : List.of());
            int inspected = Math.min(targets.size(), PRECHECK_MAX);
            for (int i = 0; i < inspected; i++) {
                MatchReplaceTarget t = targets.get(i);
                if (!engine.inScope(t)) {
                    outOfScope++;
                    continue;
                }
                HttpRequest req = t.messages() == null ? null : t.messages().request();
                for (RunIdentity id : ids) {
                    if (req == null || MatchReplaceEngine.buildRequest(req, id.rules()) == null) noApply++;
                }
            }
            List<String> warn = new ArrayList<>();
            if (outOfScope > 0) warn.add("⚠ " + outOfScope + " out of scope (skipped)");
            if (noApply > 0) warn.add("⚠ " + noApply + " request(s) where a rule doesn't apply");
            long now = java.time.Instant.now().getEpochSecond();
            long expired = ticked.stream().map(sessions::get).filter(java.util.Objects::nonNull)
                    .filter(id -> id.tokenInfo() != null && id.tokenInfo().expired(now)).count();
            if (expired > 0) warn.add("⚠ " + expired + " session(s) with an expired token");
            precheck.setText(warn.isEmpty() ? "✓ pre-check OK" : String.join("   ", warn));
            precheck.setForeground(warn.isEmpty() ? SwingColors.OK : SwingColors.HIGH);

            int requests = targets.size() * ticked.size();
            long secs = MatchReplaceEngine.estimateSeconds(requests, (Integer) delay.getValue());
            summary.setText(targets.size() + " targets × " + ticked.size() + " sessions = " + requests + " requests"
                    + (requests > 1 ? "  ·  at least ~" + human(secs) : ""));
            send.setText("Send " + requests + " requests (ACTIVE)");
            send.setEnabled(requests > 0 && err == null);
            updatePreview();
        }

        void updatePreview() {
            int ti = targetBox.getSelectedIndex();
            Object sname = sessionBox.getSelectedItem();
            if (ti < 0 || sname == null) {
                setText(before, List.of(), true);
                setText(after, List.of(), false);
                diffInfo.setText("  tick a session to preview");
                diffInfo.setForeground(SwingColors.MUTED);
                return;
            }
            HttpRequestResponse rr = targets.get(ti).messages();
            HttpRequest req = rr == null ? null : rr.request();
            if (req == null) {
                diffInfo.setText("  (no captured request for this target)");
                setText(before, List.of(), true);
                setText(after, List.of(), false);
                return;
            }
            String err = extra.error();
            List<RunIdentity> ids = identities(List.of(String.valueOf(sname)), sessions,
                    err == null ? extra.rules() : List.of());
            HttpRequest out = ids.isEmpty() ? null : MatchReplaceEngine.buildRequest(req, ids.get(0).rules());
            String a = truncate(req.toString());
            String b = out == null ? "" : truncate(out.toString());
            List<LineDiff.Line> d = LineDiff.diff(a, b);
            setText(before, d, true);
            setText(after, d, false);
            diffInfo.setText(out == null ? "  ⚠ a rule doesn't apply to this request (it would be skipped)"
                    : "  " + LineDiff.changes(d) + " line(s) changed");
            diffInfo.setForeground(out == null ? SwingColors.HIGH : SwingColors.MUTED);
        }

        void submit() {
            String err = extra.error();
            if (err != null) {
                JOptionPane.showMessageDialog(dialog, err, "ReconHub", JOptionPane.WARNING_MESSAGE);
                return;
            }
            settings.setMatchReplaceDelayMs((Integer) delay.getValue());
            settings.setMatchReplaceConcurrency((Integer) conc.getValue());
            List<String> ticked = ticked();
            lastSessions = new LinkedHashSet<>(ticked);
            lastExtraRules = extra.rules();
            MatchReplaceJob job = engine.submitAs(targets, identities(ticked, sessions, extra.rules()));
            if (job == null) {
                JOptionPane.showMessageDialog(dialog,
                        "Refused — Match & Replace may have been turned off, or there was nothing to send.",
                        "ReconHub", JOptionPane.WARNING_MESSAGE);
                return;
            }
            dialog.dispose();
            onSubmitted.accept(job);
        }
    }

    // ---- helpers -------------------------------------------------------------------------

    private static final Color ADD_BG = new Color(46, 160, 67, 70);
    private static final Color DEL_BG = new Color(248, 81, 73, 70);

    private static void setText(JTextPane p, List<LineDiff.Line> lines, boolean beforeSide) {
        StyledDocument doc = p.getStyledDocument();
        try {
            doc.remove(0, doc.getLength());
            SimpleAttributeSet plain = new SimpleAttributeSet();
            SimpleAttributeSet mark = new SimpleAttributeSet();
            StyleConstants.setBackground(mark, beforeSide ? DEL_BG : ADD_BG);
            for (LineDiff.Line l : lines) {
                if (beforeSide && l.op() == LineDiff.Op.ADDED) continue;
                if (!beforeSide && l.op() == LineDiff.Op.REMOVED) continue;
                boolean changed = l.op() != LineDiff.Op.SAME;
                doc.insertString(doc.getLength(), (changed ? (beforeSide ? "- " : "+ ") : "  ") + l.text() + "\n",
                        changed ? mark : plain);
            }
            p.setCaretPosition(0);
        } catch (BadLocationException ignored) {
            // appends can't fail
        }
    }

    private static JTextPane pane() {
        JTextPane p = new JTextPane();
        p.setEditable(false);
        p.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        return p;
    }

    private static JPanel titled(String title, JTextPane p) {
        JPanel x = new JPanel(new BorderLayout());
        JLabel l = new JLabel(title);
        l.setForeground(SwingColors.MUTED);
        x.add(l, BorderLayout.NORTH);
        x.add(new JScrollPane(p), BorderLayout.CENTER);
        return x;
    }

    private static JPanel flow() {
        return new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
    }

    private static String label(MatchReplaceTarget t) {
        return (t.method() == null ? "" : t.method() + " ") + t.host() + t.path();
    }

    private static String truncate(String s) {
        if (s == null) return "";
        return s.length() > PREVIEW_MAX ? s.substring(0, PREVIEW_MAX) + "\n…(truncated)" : s;
    }

    static String human(long secs) {
        if (secs < 60) return secs + " s";
        if (secs < 3600) return (secs / 60) + " min " + (secs % 60) + " s";
        return (secs / 3600) + " h " + (secs % 3600 / 60) + " min";
    }
}
