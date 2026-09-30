package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.active.MatchReplaceEngine;
import com.reconhub.active.MatchReplaceJob;
import com.reconhub.active.MatchReplaceResult;

import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

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

    private static final String[] COLS =
            {"Host", "Path", "Method", "Status", "Length", "Time", "Error"};
    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final MatchReplaceEngine engine;
    private final MessageViewer viewer;
    // Accumulated across every job this session -- MatchReplaceJob itself only holds one run's results,
    // same relationship BruteforceJob has to BruteforcePanel's HitModel cache.
    private final List<MatchReplaceResult> results = new ArrayList<>();

    public MatchReplacePanel(MontoyaApi api, MatchReplaceEngine engine) {
        super(api, null);   // no Bookmarks -- a send result isn't user-authored data worth bookmarking
        this.engine = engine;
        this.viewer = new MessageViewer(api);
        installDetail(viewer);
        engine.setListener(this);

        JButton clear = new JButton("Clear results");
        clear.addActionListener(e -> {
            int choice = JOptionPane.showConfirmDialog(this, "Clear all Match & Replace results?",
                    "ReconHub", JOptionPane.OK_CANCEL_OPTION);
            if (choice == JOptionPane.OK_OPTION) {
                synchronized (results) {
                    results.clear();
                }
                refreshData();
            }
        });
        addToToolbar(clear);
    }

    @Override
    public void refreshData() {
        // Pull in every result from every job that's landed since the last refresh -- cheap (jobs are
        // few, results per job bounded by what the user selected) and avoids needing a separate "new
        // results since last poll" cursor.
        synchronized (results) {
            for (MatchReplaceJob job : engine.jobs()) {
                for (MatchReplaceResult r : job.getResults()) {
                    if (!results.contains(r)) {
                        results.add(r);
                    }
                }
            }
        }
        super.refreshData();
    }

    @Override protected List<MatchReplaceResult> supplyRows() {
        synchronized (results) {
            return new ArrayList<>(results);
        }
    }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{160, 260, 60, 60, 70, 80, 200};
    }

    // Status/Length are numeric -- see AbstractTablePanel.java's CLAUDE.md note on why this is required
    // for the sorter to compare them as numbers instead of lexicographically.
    @Override protected Class<?>[] columnClasses() {
        return new Class<?>[]{null, null, null, Integer.class, Integer.class, null, null};
    }

    @Override
    protected Object valueAt(MatchReplaceResult r, int c) {
        return switch (c) {
            case 0 -> r.getHost();
            case 1 -> r.getPath();
            case 2 -> r.getMethod();
            case 3 -> r.getStatus() == 0 ? null : r.getStatus();
            case 4 -> r.getLengthBytes() == 0 && r.getMessages() == null ? null : r.getLengthBytes();
            case 5 -> TS.format(Instant.ofEpochMilli(r.getTimestamp()));
            case 6 -> r.getError() == null ? "" : r.getError();
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
            return;
        }
        viewer.show(r.getMessages());
        viewer.setInfo(r.getError() != null ? "Error: " + r.getError()
                : r.getMethod() + " " + r.getHost() + r.getPath());
    }

    @Override public void onProgress(MatchReplaceJob job) {
        SwingUtilities.invokeLater(this::refreshData);
    }

    @Override public void onDone(MatchReplaceJob job) {
        SwingUtilities.invokeLater(this::refreshData);
    }
}
