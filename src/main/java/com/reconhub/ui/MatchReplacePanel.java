package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.active.MatchReplaceEngine;
import com.reconhub.active.MatchReplaceJob;
import com.reconhub.active.MatchReplaceResult;
import com.reconhub.active.ResponseCompare;

import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPopupMenu;
import javax.swing.JToggleButton;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Results tab for the Match & Replace bulk-send feature (0.42.0) -- one row per endpoint the feature
 * tried to send to, across every run this session (results accumulate, cleared only via the "Clear
 * results" button). <b>ACTIVE</b> results, not scraped traffic: not backed by {@link
 * com.reconhub.core.DataStore}, so nothing here is included in exports or State backups (see the plan's
 * "범위 밖" note -- may be added later like bruteforce Jobs/Hits were).
 *
 * <p>An ordinary {@link AbstractTablePanel} subclass (not a hand-rolled table like {@code
 * BruteforcePanel}'s Hits/Jobs/Activity-log split) specifically to get search/sort/right-click-Copy and
 * the request/response detail viewer for free -- exactly what a results table needs, and a much smaller
 * diff than replicating {@code BruteforcePanel}'s custom {@code TableModel}s for a single flat list.
 */
public final class MatchReplacePanel extends AbstractTablePanel<MatchReplaceResult>
        implements MatchReplaceEngine.Listener {

    // Verdict / Orig / Sim% / ΔLen (0.57.0): the resend compared with the originally captured response.
    // 0.61.0: + Run / Session (which identity the resend used).
    private static final String[] COLS =
            {"Run", "Session", "Host", "Path", "Method", "Status", "Verdict", "Orig", "Sim%", "ΔLen", "Length", "Time", "Error"};
    private static final int COL_VERDICT = 6;
    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final MatchReplaceEngine engine;
    private final MessageViewer viewer;
    // Accumulated across every job this session -- MatchReplaceJob itself only holds one run's results,
    // same relationship BruteforceJob has to BruteforcePanel's HitModel cache.
    private final List<MatchReplaceResult> results = new ArrayList<>();
    // Per-job "already absorbed up to this index" cursor (0.43.9) -- replaces an O(results^2) dedup
    // scan (results.contains(r), a linear identity scan, run for every result of every job on every
    // tick and every onProgress callback -- the list only grows, so the cost grew with the square of
    // the session's total result count). MatchReplaceJob has no equals()/hashCode() override, so a
    // plain HashMap already keys by identity here, same as the model row classes (see the 0.32.1 note).
    private final Map<MatchReplaceJob, Integer> consumed = new HashMap<>();
    // 0.62.0: run / outcome filter owned by MatchReplaceResultsView; original vs resend side by side.
    private volatile java.util.function.Predicate<MatchReplaceResult> extraFilter = r -> true;
    private final MessageViewer originalViewer;
    private Runnable onResultsChanged = () -> { };
    private int lastCount = -1;

    public MatchReplacePanel(MontoyaApi api, MatchReplaceEngine engine) {
        super(api, null);   // no Bookmarks -- a send result isn't user-authored data worth bookmarking
        this.engine = engine;
        this.viewer = new MessageViewer(api);
        this.originalViewer = new MessageViewer(api);
        javax.swing.JSplitPane detail = new javax.swing.JSplitPane(javax.swing.JSplitPane.HORIZONTAL_SPLIT,
                titled("Captured (original)", originalViewer), titled("Resend", viewer));
        detail.setResizeWeight(0.5);
        installDetail(detail);
        engine.setListener(this);
    }

    static javax.swing.JComponent titled(String title, MessageViewer v) {
        javax.swing.JPanel p = new javax.swing.JPanel(new java.awt.BorderLayout());
        javax.swing.JLabel l = new javax.swing.JLabel("  " + title);
        l.setForeground(SwingColors.MUTED);
        p.add(l, java.awt.BorderLayout.NORTH);
        p.add(v, java.awt.BorderLayout.CENTER);
        return p;
    }

    /** Filter applied on top of the search box (run + outcome chips). */
    void setExtraFilter(java.util.function.Predicate<MatchReplaceResult> f) {
        extraFilter = f == null ? r -> true : f;
        reapplyFilter();
    }

    /** Runs after new results are absorbed (and after clear / remove). */
    void setOnResultsChanged(Runnable r) {
        onResultsChanged = r == null ? () -> { } : r;
    }

    /** Snapshot of every absorbed result, oldest first. */
    List<MatchReplaceResult> allResults() {
        synchronized (results) {
            return new ArrayList<>(results);
        }
    }

    /** Drops one run's rows (the engine forgets the run too). */
    void removeRun(MatchReplaceJob job) {
        engine.remove(job);
        synchronized (results) {
            results.removeIf(r -> r.getRunId() == job.getId());
            consumed.remove(job);
        }
        refreshData();
    }

    /** Clears every result and finished run. */
    void clearAll() {
        for (MatchReplaceJob j : new ArrayList<>(engine.jobs())) {
            if (j.isDone()) engine.remove(j);
        }
        synchronized (results) {
            results.clear();
            consumed.clear();
        }
        refreshData();
    }

    @Override protected boolean rowIncluded(MatchReplaceResult r) {
        return r == null || extraFilter.test(r);
    }

    @Override protected boolean hasRowFilter() {
        return true;
    }

    private static ResponseCompare.Verdict verdictOf(MatchReplaceResult r) {
        return r == null || r.getCompare() == null ? null : r.getCompare().verdict();
    }

    @Override
    protected void styleCell(Component comp, MatchReplaceResult r, int viewColumn, boolean selected) {
        if (selected || viewColumn != COL_VERDICT) {
            return;
        }
        ResponseCompare.Verdict v = verdictOf(r);
        if (v == ResponseCompare.Verdict.SAME) {
            comp.setForeground(SwingColors.HIGH);
        } else if (v == ResponseCompare.Verdict.BLOCKED) {
            comp.setForeground(SwingColors.OK);
        } else if (v != null) {
            comp.setForeground(SwingColors.MUTED);
        }
    }

    @Override
    protected void extraMenuItems(JPopupMenu menu, MatchReplaceResult r) {
        menu.addSeparator();
        addMenuItem(menu, "Send this resend to Repeater", r != null && r.getMessages() != null,
                () -> api.repeater().sendToRepeater(r.getMessages().request(),
                        "RH " + (r.getIdentity().isEmpty() ? "" : r.getIdentity() + " ") + r.getPath()));
    }

    @Override
    public void refreshData() {
        // Pull in every result from every job that's landed since the last refresh, via each job's own
        // cursor (0.43.9) -- see `consumed`'s field comment for why this replaced an O(n^2) dedup scan.
        // The new cursor value is the actual size of what resultsFrom() returned, not a freshly-reread
        // job.resultCount() -- a concurrent recordResult() between the two calls could otherwise skip a
        // result forever instead of just picking it up one tick later.
        synchronized (results) {
            for (MatchReplaceJob job : engine.jobs()) {
                int from = consumed.getOrDefault(job, 0);
                List<MatchReplaceResult> newOnes = job.resultsFrom(from);
                if (!newOnes.isEmpty()) {
                    results.addAll(newOnes);
                    consumed.put(job, from + newOnes.size());
                }
            }
        }
        super.refreshData();
        int n;
        synchronized (results) {
            n = results.size();
        }
        if (n != lastCount || engine.jobs().stream().anyMatch(j -> !j.isDone())) {
            lastCount = n;
            onResultsChanged.run();
        }
    }

    @Override protected List<MatchReplaceResult> supplyRows() {
        synchronized (results) {
            return new ArrayList<>(results);
        }
    }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{45, 110, 160, 260, 60, 60, 80, 55, 55, 70, 70, 80, 200};
    }

    // Status/Length are numeric -- see AbstractTablePanel.java's CLAUDE.md note on why this is required
    // for the sorter to compare them as numbers instead of lexicographically. Static constant (0.43.8)
    // -- see EndpointsPanel's identical note.
    private static final Class<?>[] COLUMN_CLASSES =
            {Integer.class, null, null, null, null, Integer.class, null, Integer.class, Integer.class, Integer.class,
             Integer.class, null, null};

    @Override protected Class<?>[] columnClasses() {
        return COLUMN_CLASSES;
    }

    @Override
    protected Object valueAt(MatchReplaceResult r, int c) {
        return switch (c) {
            case 0 -> r.getRunId() == 0 ? null : r.getRunId();
            case 1 -> r.getIdentity();
            case 2 -> r.getHost();
            case 3 -> r.getPath();
            case 4 -> r.getMethod();
            case 5 -> r.getStatus() == 0 ? null : r.getStatus();
            case 6 -> r.getCompare() == null ? "" : r.getCompare().verdict().label();
            case 7 -> r.getCompare() == null || r.getCompare().origStatus() == 0 ? null : r.getCompare().origStatus();
            case 8 -> r.getCompare() == null || r.getCompare().similarity() < 0 ? null
                    : (int) Math.round(r.getCompare().similarity() * 100);
            case 9 -> r.getCompare() == null || r.getCompare().verdict() == ResponseCompare.Verdict.NA ? null
                    : r.getCompare().lengthDelta();
            case 10 -> r.getLengthBytes() == 0 && r.getMessages() == null ? null : r.getLengthBytes();
            case 11 -> TS.format(Instant.ofEpochMilli(r.getTimestamp()));
            case 12 -> r.getError() == null ? "" : r.getError();
            default -> "";
        };
    }

    @Override protected HttpRequestResponse rowMessages(MatchReplaceResult r) {
        return r == null ? null : r.getMessages();
    }

    @Override
    protected void onRowSelected(MatchReplaceResult r) {
        if (r == null) {
            viewer.show(null);
            viewer.setInfo(" ");
            originalViewer.show(null);
            originalViewer.setInfo(" ");
            return;
        }
        originalViewer.show(r.getOriginal());
        originalViewer.setInfo(r.getOriginal() == null ? "(no captured exchange)" : "As captured");
        viewer.show(r.getMessages());
        ResponseCompare.Result c = r.getCompare();
        String cmp = c == null || c.verdict() == ResponseCompare.Verdict.NA ? ""
                : "  |  " + c.verdict().label() + " vs. captured (HTTP " + c.origStatus() + ", "
                        + Math.round(c.similarity() * 100) + "% similar"
                        + (c.verdict() == ResponseCompare.Verdict.SAME ? " -- same data for this identity: authz bypass?"
                        : "") + ")";
        viewer.setInfo(r.getError() != null ? "Error: " + r.getError()
                : (r.getIdentity().isEmpty() ? "" : "[" + r.getIdentity() + "] ") + r.getMethod() + " " + r.getHost()
                        + r.getPath() + cmp);
    }

    @Override public void onProgress(MatchReplaceJob job) {
        SwingUtilities.invokeLater(this::refreshData);
    }

    @Override public void onDone(MatchReplaceJob job) {
        SwingUtilities.invokeLater(this::refreshData);
    }
}
