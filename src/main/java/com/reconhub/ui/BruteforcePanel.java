package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import com.reconhub.active.BruteforceEngine;
import com.reconhub.active.BruteforceJob;
import com.reconhub.active.KnownPaths;
import com.reconhub.core.Settings;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Known-path bruteforce tab. <b>ACTIVE</b> — this is the only place in ReconHub that sends its own
 * traffic to a target. There is no separate master on/off switch here: runs are started from a host
 * row's right-click menu (Dashboard/Tech/Endpoints/Parameters), and the confirmation dialog shown
 * there (with an editable target field) is the sole, mandatory gate — see {@link RunBruteforceAction}.
 * This tab holds the throttle, wordlist, the running/finished job list, and an activity log of every
 * path probed and the response it got. Discovered endpoints/findings show up in the existing Endpoints
 * (Source=bruteforce) and Findings tabs — no separate results grid.
 */
public final class BruteforcePanel extends JPanel implements Refreshable, BruteforceEngine.Listener {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final MontoyaApi api;
    private final Settings settings;
    private final BruteforceEngine engine;

    private final JLabel wordlistInfo = new JLabel();
    private final JobModel jobModel = new JobModel();
    private final JTable jobTable = new JTable(jobModel);
    private final HitModel hitModel = new HitModel();
    private final JTable hitTable = new JTable(hitModel);
    private final JTextArea logArea = new JTextArea();

    public BruteforcePanel(MontoyaApi api, Settings settings, BruteforceEngine engine) {
        this.api = api;
        this.settings = settings;
        this.engine = engine;
        setLayout(new BorderLayout(0, 10));
        setBorder(BorderFactory.createEmptyBorder(12, 14, 12, 14));

        JPanel top = new JPanel();
        top.setLayout(new javax.swing.BoxLayout(top, javax.swing.BoxLayout.Y_AXIS));
        top.add(banner());
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
                + "Parameters and choose \"Run known-path bruteforce on this host…\" — the confirmation "
                + "dialog there lets you edit the target address and is required every run. Confirmed "
                + "hits are listed below (Hits tab) and also appear in Endpoints (Source=bruteforce) "
                + "and, for exposed files / admin surfaces, in Findings."));

        add(top, BorderLayout.NORTH);

        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JTabbedPane center = new JTabbedPane();
        center.addTab("Hits", hitsPanel());
        center.addTab("Jobs", jobsPanel());
        center.addTab("Activity log", logPanel());
        add(center, BorderLayout.CENTER);

        updateWordlistInfo();
        engine.setListener(this);
    }

    private JComponent banner() {
        JLabel l = new JLabel("⚠  ACTIVE known-path bruteforce — for AUTHORIZED targets only. "
                + "Sends requests for every path in the wordlist. Runs only on a host you explicitly "
                + "pick, after you confirm (and can edit the target) in the dialog.");
        l.setOpaque(true);
        l.setBackground(SwingColors.bannerBg());
        l.setForeground(SwingColors.bannerFg());
        l.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(SwingColors.severityFg(com.reconhub.model.Finding.Severity.HIGH)),
                BorderFactory.createEmptyBorder(8, 12, 8, 12)));
        l.setFont(l.getFont().deriveFont(Font.BOLD, 13f));
        l.setAlignmentX(LEFT_ALIGNMENT);
        return l;
    }

    private interface IntSetter { void set(int v); }

    private JPanel spinnerRow(String label, int value, int min, int max, int step, IntSetter setter) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        p.setAlignmentX(LEFT_ALIGNMENT);
        p.add(new JLabel(label));
        JSpinner sp = new JSpinner(new SpinnerNumberModel(value, min, max, step));
        sp.addChangeListener(e -> setter.set((Integer) sp.getValue()));
        p.add(sp);
        return p;
    }

    private JPanel wordlistRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
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
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        buttons.add(cancelSelected);
        buttons.add(cancelAll);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(new JScrollPane(jobTable), BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.SOUTH);
        return panel;
    }

    /** All confirmed hits across every job (running or finished), newest job first. Called only from
     * {@code HitModel.fireChanged()} -- do not call from getRowCount()/getValueAt() (Swing's renderer
     * calls those once per visible cell per repaint, which used to rebuild this whole list every time). */
    private List<Map.Entry<BruteforceJob, BruteforceJob.Hit>> buildHits() {
        List<Map.Entry<BruteforceJob, BruteforceJob.Hit>> out = new ArrayList<>();
        List<BruteforceJob> jobs = engine.jobs();
        for (int j = jobs.size() - 1; j >= 0; j--) {
            BruteforceJob job = jobs.get(j);
            for (BruteforceJob.Hit hit : job.getHitList()) {
                out.add(new AbstractMap.SimpleEntry<>(job, hit));
            }
        }
        return out;
    }

    private JComponent hitsPanel() {
        hitTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        hitTable.setRowHeight(22);
        int[] widths = {160, 220, 60, 80, 70};
        for (int i = 0; i < widths.length; i++) {
            hitTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        hitTable.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { maybeShow(e); }
            @Override public void mouseReleased(MouseEvent e) { maybeShow(e); }
            private void maybeShow(MouseEvent e) {
                if (!e.isPopupTrigger()) {
                    return;
                }
                int row = hitTable.rowAtPoint(e.getPoint());
                if (row < 0) {
                    return;
                }
                hitTable.setRowSelectionInterval(row, row);
                hitPopup(row).show(hitTable, e.getX(), e.getY());
            }
        });

        JLabel hint = new JLabel("Full detail (request/response) for each hit is in the Endpoints tab "
                + "(Source=bruteforce) and, for exposed/admin/api hits, Findings.");
        hint.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(hint, BorderLayout.NORTH);
        panel.add(new JScrollPane(hitTable), BorderLayout.CENTER);
        return panel;
    }

    private JPopupMenu hitPopup(int row) {
        JPopupMenu menu = new JPopupMenu();
        // Must read the SAME list the table is currently displaying, not rebuild -- otherwise a hit
        // landing between repaint and right-click could shift row indices out from under this.
        List<Map.Entry<BruteforceJob, BruteforceJob.Hit>> hits = hitModel.hits();
        if (row < 0 || row >= hits.size()) {
            return menu;
        }
        BruteforceJob job = hits.get(row).getKey();
        BruteforceJob.Hit hit = hits.get(row).getValue();
        String url = job.getBaseUrl() + hit.path();
        JMenuItem copyPath = new JMenuItem("Copy path");
        copyPath.addActionListener(e -> UiUtil.copyToClipboard(hit.path()));
        menu.add(copyPath);
        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> UiUtil.copyToClipboard(url));
        menu.add(copyUrl);
        JMenuItem open = new JMenuItem("Open in browser");
        open.addActionListener(e -> UiUtil.openInBrowser(api, url));
        menu.add(open);
        return menu;
    }

    private JComponent logPanel() {
        JButton clear = new JButton("Clear log");
        clear.addActionListener(e -> logArea.setText(""));
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        buttons.add(clear);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(new JScrollPane(logArea), BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.SOUTH);
        return panel;
    }

    // ---- BruteforceEngine.Listener (called off the EDT) ------------------

    @Override
    public void onProgress(BruteforceJob job) {
        SwingUtilities.invokeLater(() -> {
            jobModel.fireChanged();
            hitModel.fireChanged();
        });
    }

    @Override
    public void onDone(BruteforceJob job) {
        SwingUtilities.invokeLater(() -> {
            jobModel.fireChanged();
            hitModel.fireChanged();
        });
    }

    @Override
    public void onLog(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append("[" + LocalTime.now().format(TS) + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    @Override
    public void refreshData() {
        jobModel.fireChanged();
        hitModel.fireChanged();
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
     * multi-line hint text uses a non-editable {@link JTextArea} instead.
     */
    private static JComponent wrappedText(String text) {
        JTextArea area = new JTextArea(text);
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

    private final class HitModel extends AbstractTableModel {
        private static final String[] COLS = {"Host", "Path", "Status", "Length", "Tag"};

        // Rebuilt only when a hit is actually recorded (fireChanged()), not on every getRowCount()/
        // getValueAt() call -- Swing calls the latter once per visible cell per repaint, which used to
        // walk every job's hit list on every single cell paint. Declared here (an inner-class instance
        // field) so it's initialized during `new HitModel()`, before `hitTable = new JTable(hitModel)`
        // (the next field) ever calls getRowCount().
        private List<Map.Entry<BruteforceJob, BruteforceJob.Hit>> cache = List.of();

        void fireChanged() {
            cache = buildHits();
            fireTableDataChanged();
        }

        List<Map.Entry<BruteforceJob, BruteforceJob.Hit>> hits() { return cache; }

        @Override public int getRowCount() { return cache.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public boolean isCellEditable(int r, int c) { return false; }

        @Override
        public Object getValueAt(int r, int c) {
            if (r < 0 || r >= cache.size()) {
                return "";
            }
            BruteforceJob job = cache.get(r).getKey();
            BruteforceJob.Hit hit = cache.get(r).getValue();
            return switch (c) {
                case 0 -> job.getHost();
                case 1 -> hit.path();
                case 2 -> hit.status();
                case 3 -> hit.lengthBytes();
                case 4 -> hit.tag();
                default -> "";
            };
        }
    }
}
