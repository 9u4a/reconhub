package com.reconhub.ui;

import com.reconhub.active.BruteforceEngine;
import com.reconhub.active.BruteforceJob;
import com.reconhub.active.KnownPaths;
import com.reconhub.core.Settings;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Known-path bruteforce tab. <b>ACTIVE</b> — this is the only place in ReconHub that sends its own
 * traffic to a target. Runs are started from a host row's right-click menu (Dashboard/Tech), not from
 * here; this tab holds the master switch, throttle, wordlist, and the running/finished job list. All
 * discovered endpoints/findings show up in the existing Endpoints (Source=bruteforce) and Findings
 * tabs — no separate results grid.
 */
public final class BruteforcePanel extends JPanel implements Refreshable, BruteforceEngine.Listener {

    private final Settings settings;
    private final BruteforceEngine engine;

    private final JLabel wordlistInfo = new JLabel();
    private final JobModel jobModel = new JobModel();
    private final JTable jobTable = new JTable(jobModel);

    public BruteforcePanel(Settings settings, BruteforceEngine engine) {
        this.settings = settings;
        this.engine = engine;
        setLayout(new BorderLayout(0, 10));
        setBorder(BorderFactory.createEmptyBorder(12, 14, 12, 14));

        JPanel top = new JPanel();
        top.setLayout(new javax.swing.BoxLayout(top, javax.swing.BoxLayout.Y_AXIS));
        top.add(banner());
        top.add(strut());

        JCheckBox active = new JCheckBox("ACTIVE — probe known paths against targets "
                + "(off = nothing is ever sent)", settings.isBruteforceActiveEnabled());
        active.setForeground(new Color(0xff5c5c));
        active.setFont(active.getFont().deriveFont(Font.BOLD));
        active.setAlignmentX(LEFT_ALIGNMENT);
        active.addActionListener(e -> settings.setBruteforceActiveEnabled(active.isSelected()));
        top.add(active);
        top.add(strut());

        top.add(section("Throttle"));
        top.add(spinnerRow("Delay between requests (ms):", settings.getBruteforceDelayMs(),
                0, 60000, 25, settings::setBruteforceDelayMs));
        top.add(spinnerRow("Concurrency (paths probed in parallel per host):",
                settings.getBruteforceConcurrency(), 1, 10, 1, settings::setBruteforceConcurrency));
        top.add(spinnerRow("Max requests per host (budget):",
                settings.getBruteforceMaxRequestsPerHost(), 1, 20000, 100,
                settings::setBruteforceMaxRequestsPerHost));
        top.add(strut());

        top.add(section("Wordlist"));
        top.add(wordlistRow());
        top.add(strut());

        top.add(section("How to run"));
        top.add(wrappedText("Right-click a host in Dashboard (host scorecard), Tech, Endpoints or "
                + "Parameters and choose \"Run known-path bruteforce on this host…\" — you can edit the "
                + "target address before it runs, and every run asks for confirmation. Hits appear in "
                + "Endpoints (Source=bruteforce) and, for exposed files / admin surfaces, in Findings."));

        add(top, BorderLayout.NORTH);
        add(jobsPanel(), BorderLayout.CENTER);

        updateWordlistInfo();
        engine.setListener(this);
    }

    private JComponent banner() {
        JLabel l = new JLabel("⚠  ACTIVE known-path bruteforce — for AUTHORIZED targets only. "
                + "Sends requests for every path in the wordlist. Runs only on a host you explicitly "
                + "pick, after you confirm.");
        l.setOpaque(true);
        l.setBackground(new Color(0x3a1414));
        l.setForeground(new Color(0xff8a8a));
        l.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0xff5c5c)),
                BorderFactory.createEmptyBorder(8, 12, 8, 12)));
        l.setFont(l.getFont().deriveFont(Font.BOLD, 13f));
        l.setAlignmentX(LEFT_ALIGNMENT);
        return l;
    }

    private interface IntSetter { void set(int v); }

    private JPanel spinnerRow(String label, int value, int min, int max, int step, IntSetter setter) {
        JPanel p = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 6, 2));
        p.setAlignmentX(LEFT_ALIGNMENT);
        p.add(new JLabel(label));
        JSpinner sp = new JSpinner(new SpinnerNumberModel(value, min, max, step));
        sp.addChangeListener(e -> setter.set((Integer) sp.getValue()));
        p.add(sp);
        return p;
    }

    private JPanel wordlistRow() {
        JPanel p = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 6, 2));
        p.setAlignmentX(LEFT_ALIGNMENT);
        p.add(wordlistInfo);
        JButton load = new JButton("Load custom wordlist file…");
        load.setToolTipText("Plain text, one path per line (optional \",tag\" suffix); # comments allowed");
        load.addActionListener(e -> loadCustomWordlist());
        p.add(load);
        JButton reset = new JButton("Reset to bundled");
        reset.addActionListener(e -> {
            engine.setWordlist(KnownPaths.loadBundled().entries());
            updateWordlistInfo();
        });
        p.add(reset);
        return p;
    }

    private void loadCustomWordlist() {
        JFileChooser fc = new JFileChooser(System.getProperty("user.home"));
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File f = fc.getSelectedFile();
        try {
            List<KnownPaths.Entry> custom = KnownPaths.loadCustomFile(f.toPath());
            if (custom.isEmpty()) {
                JOptionPane.showMessageDialog(this, "No paths found in that file.",
                        "ReconHub", JOptionPane.WARNING_MESSAGE);
                return;
            }
            int choice = JOptionPane.showConfirmDialog(this,
                    "Loaded " + custom.size() + " path(s) from " + f.getName()
                            + ".\n\nYes = replace the current wordlist, No = add to it.",
                    "ReconHub — wordlist", JOptionPane.YES_NO_CANCEL_OPTION);
            if (choice == JOptionPane.CANCEL_OPTION || choice == JOptionPane.CLOSED_OPTION) {
                return;
            }
            if (choice == JOptionPane.YES_OPTION) {
                engine.setWordlist(custom);
            } else {
                List<KnownPaths.Entry> merged = new ArrayList<>(engine.getWordlist());
                merged.addAll(custom);
                engine.setWordlist(merged);
            }
            updateWordlistInfo();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to read file: " + ex.getMessage(),
                    "ReconHub", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void updateWordlistInfo() {
        wordlistInfo.setText(engine.getWordlist().size() + " path(s) loaded.  ");
    }

    private JComponent jobsPanel() {
        jobTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        jobTable.setRowHeight(22);
        jobTable.getColumnModel().getColumn(0).setPreferredWidth(220);
        for (int i = 1; i < 4; i++) {
            jobTable.getColumnModel().getColumn(i).setPreferredWidth(90);
        }

        JButton cancelSelected = new JButton("Cancel selected");
        cancelSelected.addActionListener(e -> {
            int row = jobTable.getSelectedRow();
            if (row >= 0 && row < engine.jobs().size()) {
                engine.jobs().get(row).cancel();
            }
        });
        JButton cancelAll = new JButton("Cancel all");
        cancelAll.addActionListener(e -> {
            for (BruteforceJob j : engine.jobs()) {
                if (!j.isDone()) {
                    j.cancel();
                }
            }
        });
        JPanel buttons = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 6, 4));
        buttons.add(cancelSelected);
        buttons.add(cancelAll);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(section("Jobs"), BorderLayout.NORTH);
        panel.add(new JScrollPane(jobTable), BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.SOUTH);
        return panel;
    }

    // ---- BruteforceEngine.Listener (called off the EDT) ------------------

    @Override
    public void onProgress(BruteforceJob job) {
        SwingUtilities.invokeLater(jobModel::fireChanged);
    }

    @Override
    public void onDone(BruteforceJob job) {
        SwingUtilities.invokeLater(jobModel::fireChanged);
    }

    @Override
    public void refreshData() {
        jobModel.fireChanged();
    }

    private static JComponent section(String title) {
        JLabel l = new JLabel(title);
        l.setFont(l.getFont().deriveFont(Font.BOLD, 14f));
        l.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0));
        l.setAlignmentX(LEFT_ALIGNMENT);
        return l;
    }

    private static Component strut() {
        return Box.createVerticalStrut(10);
    }

    /**
     * A plain, word-wrapping block of text styled to look like a label. Burp's Swing look-and-feel
     * does not render {@code <html>} markup in {@code JLabel} (tags show up as literal text), so
     * multi-line hint text uses a non-editable {@link javax.swing.JTextArea} instead.
     */
    private static JComponent wrappedText(String text) {
        javax.swing.JTextArea area = new javax.swing.JTextArea(text);
        area.setEditable(false);
        area.setFocusable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setOpaque(false);
        area.setBorder(null);
        area.setFont(new JLabel().getFont());
        area.setAlignmentX(LEFT_ALIGNMENT);
        return area;
    }

    private final class JobModel extends AbstractTableModel {
        private static final String[] COLS = {"Host", "Status", "Sent/Budget", "Hits"};

        void fireChanged() { fireTableDataChanged(); }

        @Override public int getRowCount() { return engine.jobs().size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public boolean isCellEditable(int r, int c) { return false; }

        @Override
        public Object getValueAt(int r, int c) {
            List<BruteforceJob> jobs = engine.jobs();
            if (r < 0 || r >= jobs.size()) {
                return "";
            }
            BruteforceJob j = jobs.get(r);
            return switch (c) {
                case 0 -> j.getHost();
                case 1 -> j.isCancelled() ? "Cancelled" : j.isDone() ? "Done" : "Running";
                case 2 -> j.getSent() + " / " + j.getBudget();
                case 3 -> j.getHits();
                default -> "";
            };
        }
    }
}
