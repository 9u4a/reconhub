package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import com.reconhub.active.BruteforceEngine;
import com.reconhub.analysis.PayloadCheatsheet;
import com.reconhub.core.Bookmarks;
import com.reconhub.core.DataStore;
import com.reconhub.core.Settings;
import com.reconhub.core.TrafficIngestor;

import javax.swing.AbstractAction;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
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

    /** Call once at extension startup, before any UI is built -- forwards to the package-private
     * {@code SwingColors.init(...)} so that class doesn't need to be made public just for this one
     * cross-package call from {@code ReconHubExtension}. */
    public static void initTheme(MontoyaApi api) {
        SwingColors.init(api);
    }

    private final List<Refreshable> refreshables = new ArrayList<>();
    private final Map<Component, Refreshable> refreshableByTab = new IdentityHashMap<>();
    private final JTabbedPane tabs = new JTabbedPane();
    private final Timer refreshTimer;
    // Last polled value, so the 300ms tick only repaints on an actual flip (Burp's Theme API has no
    // change callback -- see SwingColors -- so this is the one place that notices a live theme switch).
    private boolean lastKnownDark = SwingColors.isDark();

    public MainTab(MontoyaApi api, DataStore store, Settings settings, TrafficIngestor ingestor,
                   PayloadCheatsheet cheatsheet, BruteforceEngine bruteforce, Bookmarks bookmarks) {
        setLayout(new BorderLayout());

        DashboardPanel dashboard = new DashboardPanel(store, api);
        EndpointsPanel endpoints = new EndpointsPanel(store, api, cheatsheet, bookmarks);
        ParametersPanel parameters = new ParametersPanel(store, api, cheatsheet, bookmarks);
        FindingsPanel findings = new FindingsPanel(store, settings, api, cheatsheet, bookmarks);
        JsAssetsPanel jsAssets = new JsAssetsPanel(store, api, ingestor, bookmarks);
        TechPanel tech = new TechPanel(store, api, bookmarks);
        SettingsPanel settingsPanel = new SettingsPanel(api, store, settings, ingestor, bruteforce, bookmarks);
        BruteforcePanel bruteforcePanel = new BruteforcePanel(api, settings, bruteforce);
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

        installKeyboardShortcuts();

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

        // Separate from refreshTimer above, which only fires on actual data changes (it's a one-shot
        // debounce, restarted by onDataChanged() -- it would sit idle for an entire quiet session with
        // no traffic). Burp's Theme API has no change callback (see SwingColors), so this is the only
        // way to notice a live light/dark flip; 1s is frequent enough to feel immediate without being
        // wasteful, since a no-op poll is just one enum comparison.
        Timer themeTimer = new Timer(1000, e -> pollTheme());
        themeTimer.start();

        store.addChangeListener(this);
        refreshAll();
    }

    /** Ctrl+1..8 switch tabs, Ctrl+F focuses the current tab's search field (a no-op on tabs without
     * one, e.g. Bruteforce/Settings). WHEN_IN_FOCUSED_WINDOW so these work regardless of which child
     * component (table, search field, ...) currently has focus. */
    private void installKeyboardShortcuts() {
        var inputMap = getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
        var actionMap = getActionMap();
        int mask = InputEvent.CTRL_DOWN_MASK;
        for (int i = 0; i < tabs.getTabCount() && i < 9; i++) {
            int index = i;
            String key = "reconhub.tab" + i;
            inputMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_1 + i, mask), key);
            actionMap.put(key, new AbstractAction() {
                @Override public void actionPerformed(ActionEvent e) { tabs.setSelectedIndex(index); }
            });
        }
        inputMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_F, mask), "reconhub.focusSearch");
        actionMap.put("reconhub.focusSearch", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) {
                if (tabs.getSelectedComponent() instanceof AbstractTablePanel<?> p) {
                    p.focusSearch();
                }
            }
        });
    }

    /** Re-polls Burp's current theme (no change-notification callback exists -- see SwingColors) and
     * repaints only on an actual flip. Cheap: a repaint re-derives colors at paint time, no data/model
     * rebuild. */
    private void pollTheme() {
        boolean dark = SwingColors.isDark();
        if (dark != lastKnownDark) {
            lastKnownDark = dark;
            repaint();
        }
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
