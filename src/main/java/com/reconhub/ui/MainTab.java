package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import com.reconhub.active.BruteforceEngine;
import com.reconhub.analysis.PayloadCheatsheet;
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

    public MainTab(MontoyaApi api, DataStore store, Settings settings, TrafficIngestor ingestor,
                   PayloadCheatsheet cheatsheet, BruteforceEngine bruteforce) {
        setLayout(new BorderLayout());

        DashboardPanel dashboard = new DashboardPanel(store);
        EndpointsPanel endpoints = new EndpointsPanel(store, api);
        ParametersPanel parameters = new ParametersPanel(store, api, cheatsheet);
        FindingsPanel findings = new FindingsPanel(store, settings, api, cheatsheet);
        JsAssetsPanel jsAssets = new JsAssetsPanel(store, api, ingestor);
        TechPanel tech = new TechPanel(store, api);
        SettingsPanel settingsPanel = new SettingsPanel(api, store, settings, ingestor);
        BruteforcePanel bruteforcePanel = new BruteforcePanel(settings, bruteforce);
        dashboard.setBruteforce(bruteforce, settings);
        tech.setBruteforce(bruteforce, settings);
        endpoints.setBruteforce(bruteforce, settings);
        parameters.setBruteforce(bruteforce, settings);
        findings.setBruteforce(bruteforce);

        refreshables.add(dashboard);
        refreshables.add(endpoints);
        refreshables.add(parameters);
        refreshables.add(findings);
        refreshables.add(jsAssets);
        refreshables.add(tech);
        refreshables.add(bruteforcePanel);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Dashboard", dashboard);
        tabs.addTab("Endpoints", endpoints);
        tabs.addTab("Parameters", parameters);
        tabs.addTab("Findings", findings);
        tabs.addTab("JS Assets", jsAssets);
        tabs.addTab("Tech", tech);
        tabs.addTab("Bruteforce", bruteforcePanel);
        // Settings is a tall stack of sections — scroll it so lower sections stay reachable at
        // any window height / half width.
        javax.swing.JScrollPane settingsScroll = new javax.swing.JScrollPane(settingsPanel,
                javax.swing.JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        settingsScroll.getVerticalScrollBar().setUnitIncrement(16);
        settingsScroll.setBorder(null);
        tabs.addTab("Settings", settingsScroll);
        add(tabs, BorderLayout.CENTER);

        // Let dashboard/findings rows jump to a filtered view of another tab.
        DashboardPanel.Navigator navigator = new DashboardPanel.Navigator() {
            @Override public void filterEndpoints(String q) {
                tabs.setSelectedComponent(endpoints);
                endpoints.searchFor(q);
            }
            @Override public void filterParameters(String q) {
                tabs.setSelectedComponent(parameters);
                parameters.searchFor(q);
            }
            @Override public void filterFindings(String q) {
                tabs.setSelectedComponent(findings);
                findings.searchFor(q);
            }
        };
        dashboard.setNavigator(navigator);
        findings.setNavigator(navigator);

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
