package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import com.reconhub.active.MatchReplaceEngine;
import com.reconhub.active.MatchReplaceJob;
import com.reconhub.core.DataStore;

import javax.swing.JPanel;
import javax.swing.JSplitPane;
import java.awt.BorderLayout;

/**
 * The Match &amp; Replace tab: {@link SessionsPanel} on the left (0.60.0), {@link MatchReplaceResultsView} --
 * runs, outcome chips, matrix / list -- on the right (0.62.0).
 */
final class MatchReplaceTab extends JPanel implements Refreshable {

    private final MatchReplacePanel results;
    private final MatchReplaceResultsView view;
    private final SessionsPanel sessions;

    MatchReplaceTab(MontoyaApi api, MatchReplacePanel results, MatchReplaceEngine engine, DataStore store) {
        super(new BorderLayout());
        this.results = results;
        this.sessions = new SessionsPanel(engine.sessions(), store);
        this.view = new MatchReplaceResultsView(api, engine, results);
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, sessions, view);
        split.setResizeWeight(0.0);
        split.setDividerLocation(280);
        split.setContinuousLayout(true);
        add(split, BorderLayout.CENTER);
    }

    /** Shows a run (e.g. one just submitted) in the results view. */
    void showRun(MatchReplaceJob job) {
        results.refreshData();
        view.showRun(job);
    }

    @Override
    public void refreshData() {
        results.refreshData();
        sessions.repaint();   // token expiry text is computed at paint time
    }
}
