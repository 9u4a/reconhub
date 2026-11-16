package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import com.reconhub.active.MatchReplaceEngine;
import com.reconhub.active.MatchReplaceJob;
import com.reconhub.active.MatchReplaceResult;
import com.reconhub.active.MatchReplaceTarget;
import com.reconhub.active.MatrixModel;
import com.reconhub.active.RunIdentity;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JToggleButton;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Right side of the Match &amp; Replace tab (0.62.0): the run list (progress, cancel / re-run / delete), outcome
 * chips (Same / Blocked / Different / Error, click to filter), and two views of the selected run -- the
 * <b>endpoint × session matrix</b> (default; ⚠ Same = another identity got the captured user's response)
 * and the flat result list -- each with the captured original and the resend side by side.
 */
final class MatchReplaceResultsView extends JPanel {

    private static final String ALL = "All runs";

    private final MontoyaApi api;
    private final MatchReplaceEngine engine;
    private final MatchReplacePanel list;
    private final JToggleButton listBtn = new JToggleButton("List");
    private final RunsModel runsModel = new RunsModel();
    private final JTable runs = new JTable(runsModel);
    private final JButton cancel = new JButton("Cancel");
    private final JButton rerun = new JButton("Re-run");
    private final JButton delete = new JButton("Delete run");
    private final Map<MatrixModel.Outcome, JToggleButton> chips = new EnumMap<>(MatrixModel.Outcome.class);
    private final Set<MatrixModel.Outcome> activeOutcomes = EnumSet.noneOf(MatrixModel.Outcome.class);
    private final CardLayout cards = new CardLayout();
    private final JPanel cardPanel = new JPanel(cards);
    // Declared before matrixModel / matrix: new JTable(...) queries the table model (column count) during
    // construction, so these must already be initialized (field initializers run in declaration order).
    private MatrixModel model = MatrixModel.of(List.of(), List.of());
    private List<MatrixModel.Row> visibleRows = List.of();
    private final MatrixTableModel matrixModel = new MatrixTableModel();
    private final JTable matrix = new JTable(matrixModel);
    private final MessageViewer cellOriginal;
    private final MessageViewer cellResend;
    private final JLabel empty = new JLabel(" ");
    private boolean rebuilding;
    private List<String> lastColumns = List.of();
    // Coalesces result-driven refreshes: a fast run reports every send, the view rebuilds at most ~4x/s.
    private final javax.swing.Timer refreshTimer = new javax.swing.Timer(250, e -> refresh());

    MatchReplaceResultsView(MontoyaApi api, MatchReplaceEngine engine, MatchReplacePanel list) {
        super(new BorderLayout());
        this.api = api;
        this.engine = engine;
        this.list = list;
        this.cellOriginal = new MessageViewer(api);
        this.cellResend = new MessageViewer(api);

        // ---- runs ----
        runs.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        runs.setRowHeight(22);
        runs.getColumnModel().getColumn(0).setPreferredWidth(230);
        runs.getColumnModel().getColumn(1).setPreferredWidth(160);
        runs.getColumnModel().getColumn(1).setCellRenderer((t, v, sel, f, r, c) -> {
            JProgressBar bar = new JProgressBar(0, 100);
            int[] pv = (int[]) v;
            bar.setMaximum(Math.max(1, pv[1]));
            bar.setValue(pv[0]);
            bar.setStringPainted(true);
            bar.setString(pv[1] == 0 ? "" : pv[0] + " / " + pv[1]);
            return bar;
        });
        runs.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !rebuilding) {
                updateButtons();
                rebuildView();
            }
        });
        cancel.addActionListener(e -> { MatchReplaceJob j = selectedJob(); if (j != null) j.cancel(); });
        rerun.addActionListener(e -> {
            MatchReplaceJob j = selectedJob();
            if (j == null) return;
            MatchReplaceJob again = engine.rerun(j);
            if (again == null) {
                JOptionPane.showMessageDialog(this, "Refused — Match & Replace is off in Settings.", "ReconHub",
                        JOptionPane.WARNING_MESSAGE);
            } else {
                list.refreshData();
                showRun(again);
            }
        });
        delete.addActionListener(e -> {
            MatchReplaceJob j = selectedJob();
            if (j != null && JOptionPane.showConfirmDialog(this, "Delete run " + j.label() + " and its results?",
                    "ReconHub", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                list.removeRun(j);
            }
        });
        JButton clearAll = new JButton("Clear all");
        clearAll.addActionListener(e -> {
            if (JOptionPane.showConfirmDialog(this, "Clear all finished runs and their results?", "ReconHub",
                    JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                list.clearAll();
            }
        });
        JPanel runButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        runButtons.add(new JLabel("Runs"));
        runButtons.add(cancel);
        runButtons.add(rerun);
        runButtons.add(delete);
        runButtons.add(clearAll);
        JPanel runsPanel = new JPanel(new BorderLayout());
        runsPanel.add(runButtons, BorderLayout.NORTH);
        JScrollPane runsScroll = new JScrollPane(runs);
        runsScroll.setPreferredSize(new Dimension(600, 110));
        runsPanel.add(runsScroll, BorderLayout.CENTER);

        // ---- chips + view switch ----
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JToggleButton matrixBtn = new JToggleButton("Matrix", true);
        ButtonGroup g = new ButtonGroup();
        g.add(matrixBtn);
        g.add(listBtn);
        matrixBtn.addActionListener(e -> cards.show(cardPanel, "matrix"));
        listBtn.addActionListener(e -> cards.show(cardPanel, "list"));
        bar.add(matrixBtn);
        bar.add(listBtn);
        bar.add(new JLabel("   Filter:"));
        for (MatrixModel.Outcome o : List.of(MatrixModel.Outcome.SAME, MatrixModel.Outcome.BLOCKED,
                MatrixModel.Outcome.DIFFERENT, MatrixModel.Outcome.ERROR)) {
            JToggleButton chip = new JToggleButton();
            chip.setToolTipText(switch (o) {
                case SAME -> "Another session got the same response as the captured user -- likely authorization bypass";
                case BLOCKED -> "401/403 or redirected to login -- access control held";
                case DIFFERENT -> "A different response -- check manually";
                default -> "Not sent (out of scope, a rule didn't apply, send failed)";
            });
            chip.addActionListener(e -> {
                if (chip.isSelected()) activeOutcomes.add(o); else activeOutcomes.remove(o);
                rebuildView();
            });
            chips.put(o, chip);
            bar.add(chip);
        }
        empty.setForeground(SwingColors.MUTED);
        bar.add(empty);

        // ---- matrix ----
        matrix.setRowHeight(22);
        matrix.setAutoCreateRowSorter(true);
        matrix.setCellSelectionEnabled(true);
        matrix.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        matrix.setDefaultRenderer(Object.class, new CellRenderer());
        matrix.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) showCell(); });
        matrix.getColumnModel().getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) showCell(); });
        matrix.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { popup(e); }
            @Override public void mouseReleased(MouseEvent e) { popup(e); }
        });
        JSplitPane cellDetail = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                MatchReplacePanel.titled("Captured (original)", cellOriginal), MatchReplacePanel.titled("Selected cell", cellResend));
        cellDetail.setResizeWeight(0.5);
        JSplitPane matrixSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(matrix), cellDetail);
        matrixSplit.setResizeWeight(0.55);
        cardPanel.add(matrixSplit, "matrix");
        cardPanel.add(list, "list");

        JPanel center = new JPanel(new BorderLayout());
        center.add(bar, BorderLayout.NORTH);
        center.add(cardPanel, BorderLayout.CENTER);
        JSplitPane main = new JSplitPane(JSplitPane.VERTICAL_SPLIT, runsPanel, center);
        main.setResizeWeight(0.0);
        main.setDividerLocation(150);
        add(main, BorderLayout.CENTER);

        refreshTimer.setRepeats(false);
        list.setOnResultsChanged(() -> SwingUtilities.invokeLater(() -> {
            if (!refreshTimer.isRunning()) refreshTimer.start();
        }));
        refresh();
    }

    /** Ctrl+F (0.64.0): the List card owns the search box, so switch to it and focus the field. */
    void focusSearch() {
        if (!listBtn.isSelected()) listBtn.doClick();
        list.focusSearch();
    }

    /** Selects a run (e.g. one just submitted). */
    void showRun(MatchReplaceJob job) {
        refresh();
        for (int i = 0; i < runsModel.jobs.size(); i++) {
            if (runsModel.jobs.get(i) == job) {
                runs.setRowSelectionInterval(i + 1, i + 1);
                return;
            }
        }
    }

    private MatchReplaceJob selectedJob() {
        int r = runs.getSelectedRow();
        return r <= 0 || r - 1 >= runsModel.jobs.size() ? null : runsModel.jobs.get(r - 1);
    }

    private void updateButtons() {
        MatchReplaceJob j = selectedJob();
        cancel.setEnabled(j != null && !j.isDone());
        rerun.setEnabled(j != null && j.isDone() && !j.getTargets().isEmpty());
        delete.setEnabled(j != null);
    }

    /** Re-reads runs and results (keeps the selected run). */
    void refresh() {
        MatchReplaceJob sel = selectedJob();
        boolean allSelected = runs.getSelectedRow() <= 0;
        rebuilding = true;
        try {
            List<MatchReplaceJob> jobs = new ArrayList<>(engine.jobs());
            java.util.Collections.reverse(jobs);   // newest first
            runsModel.jobs = jobs;
            runsModel.results = list.allResults();
            runsModel.fireTableDataChanged();
            int idx = sel == null ? -1 : jobs.indexOf(sel);
            if (idx >= 0) runs.setRowSelectionInterval(idx + 1, idx + 1);
            else if (allSelected || sel != null) runs.setRowSelectionInterval(0, 0);
        } finally {
            rebuilding = false;
        }
        updateButtons();
        rebuildView();
    }

    private void rebuildView() {
        MatchReplaceJob job = selectedJob();
        List<MatchReplaceResult> results = new ArrayList<>();
        for (MatchReplaceResult r : list.allResults()) {
            if (job == null || r.getRunId() == job.getId()) results.add(r);
        }
        List<String> order = new ArrayList<>();
        if (job != null) for (RunIdentity id : job.getIdentities()) order.add(id.name());
        model = MatrixModel.of(results, order);
        Map<MatrixModel.Outcome, Integer> counts = model.counts();
        chips.forEach((o, chip) -> chip.setText(label(o) + " " + counts.getOrDefault(o, 0)));
        List<MatrixModel.Row> rows = new ArrayList<>();
        for (MatrixModel.Row r : model.rows()) if (model.has(r, activeOutcomes)) rows.add(r);
        visibleRows = rows;
        int selRow = matrix.getSelectedRow();
        int selCol = matrix.getSelectedColumn();
        String keepRow = selRow >= 0 && selRow < matrix.getRowCount()
                ? visibleRowAt(selRow) == null ? null : visibleRowAt(selRow).key() : null;
        if (!model.columns().equals(lastColumns)) {
            lastColumns = new ArrayList<>(model.columns());
            matrixModel.fireTableStructureChanged();
            matrix.getColumnModel().getColumn(0).setPreferredWidth(320);
        } else {
            matrixModel.fireTableDataChanged();
        }
        if (keepRow != null) {
            for (int i = 0; i < matrix.getRowCount(); i++) {
                MatrixModel.Row r = visibleRowAt(i);
                if (r != null && r.key().equals(keepRow) && selCol >= 0 && selCol < matrix.getColumnCount()) {
                    matrix.changeSelection(i, selCol, false, false);
                    break;
                }
            }
        }
        empty.setText(results.isEmpty() ? "   No results yet -- select rows in Endpoints / Findings / Client Flows "
                + "and use \"Send N selected with Match & Replace…\"" : "");
        Set<MatrixModel.Outcome> active = EnumSet.copyOf(activeOutcomes.isEmpty()
                ? EnumSet.allOf(MatrixModel.Outcome.class) : activeOutcomes);
        int runId = job == null ? -1 : job.getId();
        list.setExtraFilter(r -> (runId < 0 || r.getRunId() == runId)
                && (activeOutcomes.isEmpty() || active.contains(MatrixModel.outcome(r))));
    }

    private MatrixModel.Row visibleRowAt(int viewRow) {
        int m = matrix.convertRowIndexToModel(viewRow);
        return m >= 0 && m < visibleRows.size() ? visibleRows.get(m) : null;
    }

    private MatchReplaceResult selectedCell() {
        int vr = matrix.getSelectedRow();
        int vc = matrix.getSelectedColumn();
        if (vr < 0 || vc < 1) return null;
        MatrixModel.Row row = visibleRowAt(vr);
        int mc = matrix.convertColumnIndexToModel(vc);
        return row == null || mc < 1 ? null : model.cell(row, model.columns().get(mc - 1));
    }

    private void showCell() {
        MatchReplaceResult r = selectedCell();
        if (r == null) {
            cellOriginal.show(null);
            cellResend.show(null);
            cellOriginal.setInfo(" ");
            cellResend.setInfo(" ");
            return;
        }
        cellOriginal.show(r.getOriginal());
        cellOriginal.setInfo("As captured");
        cellResend.show(r.getMessages());
        String cmp = r.getCompare() == null ? "" : "  |  " + r.getCompare().verdict().label() + ", "
                + Math.round(Math.max(0, r.getCompare().similarity()) * 100) + "% similar, Δlen "
                + r.getCompare().lengthDelta();
        cellResend.setInfo(r.getError() != null ? "[" + r.getIdentity() + "] Error: " + r.getError()
                : "[" + r.getIdentity() + "] HTTP " + r.getStatus() + cmp);
    }

    private void popup(MouseEvent e) {
        if (!e.isPopupTrigger()) return;
        int vr = matrix.rowAtPoint(e.getPoint());
        int vc = matrix.columnAtPoint(e.getPoint());
        if (vr < 0) return;
        matrix.changeSelection(vr, Math.max(vc, 0), false, false);
        MatchReplaceResult r = selectedCell();
        MatrixModel.Row row = visibleRowAt(vr);
        JPopupMenu m = new JPopupMenu();
        JMenuItem rep = new JMenuItem("Send this resend to Repeater");
        rep.setEnabled(r != null && r.getMessages() != null);
        rep.addActionListener(a -> api.repeater().sendToRepeater(r.getMessages().request(),
                "RH " + r.getIdentity() + " " + r.getPath()));
        m.add(rep);
        MatchReplaceJob job = selectedJob();
        MatchReplaceTarget target = job == null || row == null ? null : job.getTargets().stream()
                .filter(t -> (t.method() + " " + t.host() + t.path()).equals(row.key())).findFirst().orElse(null);
        JMenuItem again = new JMenuItem("Re-send this endpoint as every session of the run (active)");
        again.setEnabled(target != null);
        again.addActionListener(a -> {
            MatchReplaceJob j = engine.submitAs(List.of(target), job.getIdentities());
            if (j == null) {
                JOptionPane.showMessageDialog(this, "Refused — Match & Replace is off in Settings.", "ReconHub",
                        JOptionPane.WARNING_MESSAGE);
            } else {
                list.refreshData();
                showRun(j);
            }
        });
        m.add(again);
        m.show(matrix, e.getX(), e.getY());
    }

    private static String label(MatrixModel.Outcome o) {
        return switch (o) {
            case SAME -> "⚠ Same";
            case BLOCKED -> "Blocked";
            case DIFFERENT -> "Different";
            case ERROR -> "Error";
            default -> "";
        };
    }

    // ---- models / renderers ---------------------------------------------------------------

    private final class RunsModel extends AbstractTableModel {
        private final String[] cols = {"Run", "Progress", "State", "⚠ Same", "Blocked", "Different", "Error"};
        List<MatchReplaceJob> jobs = List.of();
        List<MatchReplaceResult> results = List.of();

        @Override public int getRowCount() { return jobs.size() + 1; }
        @Override public int getColumnCount() { return cols.length; }
        @Override public String getColumnName(int c) { return cols[c]; }

        @Override public Object getValueAt(int row, int c) {
            if (row == 0) {
                return switch (c) {
                    case 0 -> ALL;
                    case 1 -> new int[]{0, 0};
                    case 2 -> jobs.size() + " run(s)";
                    default -> count(-1, c);
                };
            }
            MatchReplaceJob j = jobs.get(row - 1);
            return switch (c) {
                case 0 -> j.label();
                case 1 -> new int[]{j.getSent(), j.getTotal()};
                case 2 -> j.isDone() ? (j.isCancelled() ? "Cancelled" : "Done") : (j.isCancelled() ? "Cancelling…" : "Running…");
                default -> count(j.getId(), c);
            };
        }

        private Object count(int runId, int c) {
            MatrixModel.Outcome o = switch (c) {
                case 3 -> MatrixModel.Outcome.SAME;
                case 4 -> MatrixModel.Outcome.BLOCKED;
                case 5 -> MatrixModel.Outcome.DIFFERENT;
                default -> MatrixModel.Outcome.ERROR;
            };
            int n = 0;
            for (MatchReplaceResult r : results) {
                if (runId >= 0 && r.getRunId() != runId) continue;
                if (o == MatrixModel.Outcome.SAME && MatrixModel.isBaseline(r.getIdentity())) continue;
                if (MatrixModel.outcome(r) == o) n++;
            }
            return n;
        }
    }

    private final class MatrixTableModel extends AbstractTableModel {
        @Override public int getRowCount() { return visibleRows.size(); }
        @Override public int getColumnCount() { return model.columns().size() + 1; }
        @Override public String getColumnName(int c) { return c == 0 ? "Endpoint" : model.columns().get(c - 1); }

        @Override public Object getValueAt(int r, int c) {
            MatrixModel.Row row = visibleRows.get(r);
            if (c == 0) return row.key();
            String col = model.columns().get(c - 1);
            return MatrixModel.cellText(model.cell(row, col), col);
        }
    }

    private final class CellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
            Component comp = super.getTableCellRendererComponent(t, v, sel, focus, r, c);
            comp.setFont(comp.getFont().deriveFont(Font.PLAIN));
            if (sel) return comp;
            int mc = t.convertColumnIndexToModel(c);
            if (mc == 0) {
                comp.setForeground(t.getForeground());
                return comp;
            }
            MatrixModel.Row row = visibleRowAt(r);
            String col = model.columns().get(mc - 1);
            MatchReplaceResult res = row == null ? null : model.cell(row, col);
            MatrixModel.Outcome o = MatrixModel.outcome(res);
            Color fg = t.getForeground();
            if (!MatrixModel.isBaseline(col)) {
                fg = switch (o) {
                    case SAME -> SwingColors.HIGH;
                    case BLOCKED -> SwingColors.OK;
                    case ERROR -> SwingColors.MEDIUM;
                    case DIFFERENT -> SwingColors.MUTED;
                    default -> t.getForeground();
                };
                if (o == MatrixModel.Outcome.SAME) comp.setFont(comp.getFont().deriveFont(Font.BOLD));
            } else {
                fg = SwingColors.MUTED;
            }
            comp.setForeground(fg);
            if (comp instanceof javax.swing.JComponent jc) {
                jc.setToolTipText(res == null || res.getCompare() == null ? null
                        : res.getCompare().verdict().label() + " · " + Math.round(Math.max(0, res.getCompare().similarity()) * 100)
                        + "% similar · Δlen " + res.getCompare().lengthDelta() + " · captured HTTP " + res.getCompare().origStatus());
            }
            return comp;
        }
    }
}
