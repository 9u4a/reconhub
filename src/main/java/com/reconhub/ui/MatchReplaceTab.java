package com.reconhub.ui;

import com.reconhub.active.MatchReplaceEngine;
import com.reconhub.core.DataStore;

import javax.swing.JPanel;
import javax.swing.JSplitPane;
import java.awt.BorderLayout;

/**
 * The Match &amp; Replace tab (0.60.0): the {@link SessionsPanel} on the left, run results on the right.
 */
final class MatchReplaceTab extends JPanel implements Refreshable {

    private final MatchReplacePanel results;
    private final SessionsPanel sessions;

    MatchReplaceTab(MatchReplacePanel results, MatchReplaceEngine engine, DataStore store) {
        super(new BorderLayout());
        this.results = results;
        this.sessions = new SessionsPanel(engine.sessions(), store);
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, sessions, results);
        split.setResizeWeight(0.0);
        split.setDividerLocation(280);
        split.setContinuousLayout(true);
        add(split, BorderLayout.CENTER);
    }

    MatchReplacePanel results() {
        return results;
    }

    @Override
    public void refreshData() {
        results.refreshData();
        sessions.repaint();   // token expiry text is computed at paint time
    }
}
