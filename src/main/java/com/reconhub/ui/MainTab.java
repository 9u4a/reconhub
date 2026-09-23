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
import java.awt.Component;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

/**
 * Top-level ReconHub suite tab. Hosts the sub-tabs and coalesces model-change notifications into a
 * single debounced refresh on the EDT (so a bulk sweep doesn't repaint thousands of times) -- and, as
 * of 0.35.0, only refreshes the currently-selected sub-tab (a background tab is refreshed once when
 * the user switches to it, via the tabs' ChangeListener, rather than 3x/second while hidden).
 */
public final class MainTab extends JPanel implements DataStore.ChangeListener {

    private final List<Refreshable> refreshables = new ArrayList<>();
    private final Map<Component, Refreshable> refreshableByTab = new IdentityHashMap<>();
    private final JTabbedPane tabs = new JTabbedPane();
    private final Timer refreshTimer;

    public MainTab(MontoyaApi api, DataStore store, Settings settings, TrafficIngestor ingestor,
                   PayloadCheatsheet cheatsheet, BruteforceEngine bruteforce) {
        setLayout(new BorderLayout());

        DashboardPanel dashboard = new DashboardPanel(store);
        EndpointsPanel endpoints = new EndpointsPanel(store, api, cheatsheet);
        ParametersPanel parameters = new ParametersPanel(store, api, cheatsheet);
        FindingsPanel findings = new FindingsPanel(store, settings, api, cheatsheet);
        JsAssetsPanel jsAssets = new JsAssetsPanel(store, api, ingestor);
        TechPanel tech = new TechPanel(store, api);
        SettingsPanel settingsPanel = new SettingsPanel(api, store, settings, ingestor, bruteforce);
        BruteforcePanel bruteforcePanel = new BruteforcePanel(settings, bruteforce);
        dashboard.setBruteforce(bruteforce, settings);
        tech.setBruteforce(bruteforce, settings);
        endpoints.setBruteforce(bruteforce, settings);
        parameters.setBruteforce(bruteforce, settings);
        findings.setBruteforce(bruteforce);

        addRefreshableTab("Dashboard", dashboard);
        addRefreshableTab("Endpoints", endpoints);
        addRefreshableTab("Parameters", parameters);
        addRefreshableTab("Findings", findings);
        addRefreshableTab("JS Assets", jsAssets);
        addRefreshableTab("Tech", tech);
        addRefreshableTab("Bruteforce", bruteforcePanel);
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
            @Override public void filterJsAssets(String q) {
                tabs.setSelectedComponent(jsAssets);
                jsAssets.searchFor(q);
            }
            @Override public void filterTech(String q) {
                tabs.setSelectedComponent(tech);
                tech.searchFor(q);
            }
        };
        dashboard.setNavigator(navigator);
        findings.setNavigator(navigator);
        jsAssets.setNavigator(navigator);

        // Switching to a tab shows current data immediately -- it hasn't been refreshed while hidden.
        tabs.addChangeListener(e -> refreshSelected());

        refreshTimer = new Timer(300, e -> refreshSelected());
        refreshTimer.setRepeats(false);

        store.addChangeListener(this);
        refreshAll();
    }

    /** Registers {@code panel} as a tab and as a {@link Refreshable} kept in sync with it. */
    private <C extends JComponent & Refreshable> void addRefreshableTab(String title, C panel) {
        tabs.addTab(title, panel);
        refreshables.add(panel);
        refreshableByTab.put(panel, panel);
    }

    /** Every registered panel once -- used only at startup, so every tab has data before it's first
     * shown (afterwards, {@link #refreshSelected()} is what the 300ms timer and tab switches call). */
    private void refreshAll() {
        for (Refreshable r : refreshables) {
            refreshOne(r);
        }
    }

    /** Refreshes only the sub-tab the user is actually looking at. */
    private void refreshSelected() {
        Refreshable r = refreshableByTab.get(tabs.getSelectedComponent());
        if (r != null) {
            refreshOne(r);
        }
    }

    private void refreshOne(Refreshable r) {
        try {
            r.refreshData();
        } catch (RuntimeException ignored) {
            // one panel failing must not stop the others
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
