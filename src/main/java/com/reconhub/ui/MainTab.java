package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import com.reconhub.core.DataStore;
import com.reconhub.core.Settings;
import com.reconhub.core.TrafficIngestor;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.List;

/**
 * Top-level ReconHub suite tab. Hosts the sub-tabs and coalesces model-change notifications into a
 * single debounced refresh on the EDT (so a bulk sweep doesn't repaint thousands of times).
 */
public final class MainTab extends JPanel implements DataStore.ChangeListener {

    private final List<Refreshable> refreshables = new ArrayList<>();
    private final Timer refreshTimer;

    public MainTab(MontoyaApi api, DataStore store, Settings settings, TrafficIngestor ingestor) {
        setLayout(new BorderLayout());

        DashboardPanel dashboard = new DashboardPanel(store);
        EndpointsPanel endpoints = new EndpointsPanel(store, api);
        ParametersPanel parameters = new ParametersPanel(store, api);
        FindingsPanel findings = new FindingsPanel(store, api);
        JsAssetsPanel jsAssets = new JsAssetsPanel(store, api);
        TechPanel tech = new TechPanel(store, api);
        SettingsPanel settingsPanel = new SettingsPanel(api, store, settings, ingestor);

        refreshables.add(dashboard);
        refreshables.add(endpoints);
        refreshables.add(parameters);
        refreshables.add(findings);
        refreshables.add(jsAssets);
        refreshables.add(tech);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Dashboard", dashboard);
        tabs.addTab("Endpoints", endpoints);
        tabs.addTab("Parameters", parameters);
        tabs.addTab("Findings", findings);
        tabs.addTab("JS Assets", jsAssets);
        tabs.addTab("Tech", tech);
        tabs.addTab("Settings", settingsPanel);
        add(tabs, BorderLayout.CENTER);

        refreshTimer = new Timer(300, e -> refreshAll());
        refreshTimer.setRepeats(false);

        store.addChangeListener(this);
        refreshAll();
    }

    private void refreshAll() {
        for (Refreshable r : refreshables) {
            try {
                r.refreshData();
            } catch (RuntimeException ignored) {
                // one panel failing must not stop the others
            }
        }
    }

    @Override
    public void onDataChanged() {
        // May be called off the EDT; restart the debounce timer on the EDT.
        SwingUtilities.invokeLater(refreshTimer::restart);
    }

    public JComponent component() {
        return this;
    }
}
