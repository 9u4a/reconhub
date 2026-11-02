package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.analysis.FindingHints;
import com.reconhub.analysis.FindingTaxonomy;
import com.reconhub.analysis.JsAnalyzer;
import com.reconhub.analysis.JsRisk;
import com.reconhub.core.Bookmarks;
import com.reconhub.core.DataStore;
import com.reconhub.core.Hosts;
import com.reconhub.model.Endpoint;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;
import com.reconhub.model.ParameterInfo;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JToggleButton;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import java.awt.Component;
import java.awt.Font;
import java.net.URI;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A focused, cross-bundle view of everything ReconHub extracted <em>from JavaScript</em> -- the
 * crypto/authz/sink/config/API-access locators (0.47.0/0.48.0) plus any secrets/comments found in JS
 * bodies. These are the same {@link Finding}s the main Findings tab holds; this tab just narrows to the
 * JS-sourced subset and groups them so an analyst can answer "what does the client-side code actually
 * do?" in one place.
 *
 * <p><b>How "JS-sourced" is decided:</b> a finding's {@code locationUrl} equals the {@link JsAsset}'s
 * URL it came from (the JS deep-analysis + JS-body scanners in {@code JsAnalyzer} all pass the JS URL as
 * the finding location). So the row set is simply every finding whose {@code locationUrl} matches a
 * known JS asset -- no new model field or source tag needed.
 */
public final class JsAnalysisPanel extends AbstractTablePanel<Finding> {

    // 0.55.0: + Seen (sensitive routes: answered in captured traffic? Y/N) + File Risk (JsRisk score of
    // the finding's JS file -- the default sort key, so the riskiest bundle's findings come first).
    private static final String[] COLS =
            {"Severity", "Category", "Type", "Match", "Seen", "JS File", "File Risk", "Evidence"};
    private static final int COL_CATEGORY = 1;
    private static final int COL_MATCH = 3;
    private static final int COL_SEEN = 4;
    private static final int COL_JS_FILE = 5;
    private static final int COL_RISK = 6;
    private static final int COL_EVIDENCE = 7;
    private static final Class<?>[] COLUMN_CLASSES =
            {null, null, null, null, null, null, Integer.class, null};
    static final String ROUTE_PREFIX = "Sensitive route in JS";

    private final DataStore store;
    private final MessageViewer viewer;
    private DashboardPanel.Navigator navigator;

    private final Set<Finding.Severity> activeSeverities = EnumSet.noneOf(Finding.Severity.class);
    private FindingTaxonomy.Category activeCategory;
    private final JComboBox<String> catBox = new JComboBox<>();
    private boolean rebuildingCatBox;
    private final ColumnValueFilter<Finding> hostFilter =
            new ColumnValueFilter<>("Host", f -> Hosts.label(f.getHost()));
    private final ColumnValueFilter<Finding> fileFilter =
            new ColumnValueFilter<>("JS file", JsAnalysisPanel::jsFileLabel);
    private final JLabel summary = new JLabel(" ");
    private final JCheckBox hideLibrary = new JCheckBox("Hide library JS", true);
    private final JCheckBox unvisitedOnly = new JCheckBox("Untested only", false);

    // Identity memos (0.55.0): this tab used to rebuild the JS-URL set and rescan every finding on every
    // 300ms tick. Each derived value below is recomputed only when its source snapshot list changes.
    private List<JsAsset> lastAssets;
    private List<Finding> lastFindings;
    private List<Finding> jsRows = List.of();
    private Set<String> libraryUrls = Set.of();
    private final JsRisk.Memo riskMemo = new JsRisk.Memo();
    private Map<String, JsRisk.Stat> stats = Map.of();
    private List<Endpoint> lastEndpoints;
    private Set<String> seenPaths = Set.of();
    private List<ParameterInfo> lastParameters;
    private Set<String> seenParams = Set.of();   // parameter names captured in traffic (0.56.0)

    public JsAnalysisPanel(DataStore store, MontoyaApi api, Bookmarks bookmarks) {
        super(api, bookmarks);
        this.store = store;
        this.viewer = new MessageViewer(api);
        installDetail(viewer, viewer);

        addToToolbar(new JLabel("  Category:"));
        rebuildCategoryItems(Map.of());
        catBox.setToolTipText("Show only this finding category (counts update live)");
        catBox.addActionListener(e -> {
            if (rebuildingCatBox) {
                return;
            }
            int i = catBox.getSelectedIndex();
            activeCategory = i <= 0 ? null : FindingTaxonomy.Category.values()[i - 1];
            onFilterChanged();
        });
        addToToolbar(catBox);

        addToToolbar(new JLabel("  Severity:"));
        for (Finding.Severity sev : Finding.Severity.values()) {
            JToggleButton b = new JToggleButton(sev.name());
            b.setToolTipText("Show only " + sev.name() + " (toggle; none selected = all)");
            b.addActionListener(e -> {
                if (b.isSelected()) {
                    activeSeverities.add(sev);
                } else {
                    activeSeverities.remove(sev);
                }
                onFilterChanged();
            });
            addToToolbar(b);
        }

        hostFilter.setOnChange(this::onFilterChanged);
        addToToolbar(hostFilter.component());
        fileFilter.setOnChange(this::onFilterChanged);
        addToToolbar(fileFilter.component());
        hideLibrary.setToolTipText("Hide findings located in library / vendor / third-party JS (view only)");
        hideLibrary.addActionListener(e -> onFilterChanged());
        addToToolbar(hideLibrary);
        unvisitedOnly.setToolTipText("Only sensitive routes / hidden parameters referenced in JS that never "
                + "appeared in captured traffic -- the untested surface");
        unvisitedOnly.addActionListener(e -> onFilterChanged());
        addToToolbar(unvisitedOnly);
        addToToolbar(summary);

        // Riskiest JS file first, its findings clustered together (header click / Shift-multi-sort still
        // work as usual -- TriStateRowSorter honors an explicit sort key).
        table.getRowSorter().setSortKeys(List.of(
                new RowSorter.SortKey(COL_RISK, SortOrder.DESCENDING),
                new RowSorter.SortKey(COL_JS_FILE, SortOrder.ASCENDING)));
    }

    /** Re-filter and refresh the summary line together (filter changes don't go through refreshData). */
    private void onFilterChanged() {
        reapplyFilter();
        updateSummary();
    }

    @Override protected String rowKey(Finding f) { return f == null ? null : f.key(); }

    @Override protected boolean hasRowFilter() { return true; }

    @Override
    protected boolean rowIncluded(Finding f) {
        if (f == null) {
            return true;
        }
        boolean sevOk = activeSeverities.isEmpty() || activeSeverities.contains(f.getSeverity());
        boolean catOk = activeCategory == null
                || FindingTaxonomy.categoryOf(f.getType()) == activeCategory;
        if (hideLibrary.isSelected() && libraryUrls.contains(f.getLocationUrl())) {
            return false;
        }
        if (unvisitedOnly.isSelected() && !Boolean.FALSE.equals(seen(f, seenPaths, seenParams))) {
            return false;
        }
        return sevOk && catOk && hostFilter.test(f) && fileFilter.test(f);
    }

    static Boolean seen(Finding f, Set<String> seenPaths) {
        return seen(f, seenPaths, Set.of());
    }

    /** For a sensitive-route finding: whether its route was seen answering in captured traffic; for a
     * hidden-parameter finding (0.56.0): whether that name was ever captured as a request parameter; null
     * for every other finding. Pure/static for headless testing. */
    static Boolean seen(Finding f, Set<String> seenPaths, Set<String> seenParams) {
        if (f == null || f.getType() == null) {
            return null;
        }
        if (f.getType().startsWith(ROUTE_PREFIX)) {
            return seenPaths.contains(JsAnalyzer.routePath(f.getRawMatch()));
        }
        if (f.getType().startsWith(JsAnalyzer.HIDDEN_PARAM_PREFIX)) {
            return seenParams.contains(f.getRawMatch());
        }
        return null;
    }

    /** Names of every captured request parameter. Pure/static for headless testing. */
    static Set<String> seenParams(List<ParameterInfo> params) {
        Set<String> out = new HashSet<>();
        for (ParameterInfo p : params) {
            out.add(p.getName());
        }
        return out;
    }

    /** Paths of endpoints that actually answered in captured traffic (status != 0), normalized like
     * {@link JsAnalyzer#routePath}. Pure/static for headless testing. */
    static Set<String> seenPaths(List<Endpoint> endpoints) {
        Set<String> out = new HashSet<>();
        for (Endpoint e : endpoints) {
            if (e.getLastStatusCode() != 0) {
                out.add(JsAnalyzer.routePath(e.getPath()));
            }
        }
        return out;
    }

    private Map<FindingTaxonomy.Category, Integer> lastCategoryCounts;

    @Override
    public void refreshData() {
        super.refreshData();
        List<Finding> rows = rows();
        Map<FindingTaxonomy.Category, Integer> counts = new EnumMap<>(FindingTaxonomy.Category.class);
        for (Finding f : rows) {
            counts.merge(FindingTaxonomy.categoryOf(f.getType()), 1, Integer::sum);
        }
        if (!counts.equals(lastCategoryCounts)) {
            rebuildCategoryItems(counts);
            lastCategoryCounts = counts;
        }
        hostFilter.refreshAvailableValues(rows);
        fileFilter.refreshAvailableValues(rows);
        updateSummary();
    }

    /** Updates the toolbar rollup line from the rows that currently pass every filter -- so narrowing to
     * one JS file turns the line into that bundle's category breakdown. */
    private void updateSummary() {
        List<Finding> visible = new ArrayList<>();
        for (Finding f : rows()) {
            if (rowIncluded(f)) {
                visible.add(f);
            }
        }
        summary.setText(summarize(visible));
    }

    /** "N files · Crypto a · Authz b · …" over {@code visible} (zero-count categories omitted). Pure/
     * static for headless testing. */
    static String summarize(List<Finding> visible) {
        Set<String> files = new HashSet<>();
        Map<FindingTaxonomy.Category, Integer> byCat =
                new EnumMap<>(FindingTaxonomy.Category.class);
        for (Finding f : visible) {
            files.add(jsFileLabel(f));
            byCat.merge(FindingTaxonomy.categoryOf(f.getType()), 1, Integer::sum);
        }
        StringBuilder sb = new StringBuilder("  ")
                .append(files.size()).append(files.size() == 1 ? " file" : " files");
        for (FindingTaxonomy.Category c : FindingTaxonomy.Category.values()) {
            int n = byCat.getOrDefault(c, 0);
            if (n > 0) {
                sb.append("  ·  ").append(c.label()).append(' ').append(n);
            }
        }
        return sb.toString();
    }

    /** Short label for a finding's JS file: the URL's filename (last path segment), or the full URL
     * when there's no usable path/filename. Pure/static for headless testing. */
    static String jsFileLabel(Finding f) {
        String url = f == null ? null : f.getLocationUrl();
        if (url == null || url.isBlank()) {
            return "(unknown)";
        }
        String path;
        try {
            path = URI.create(url).getPath();
        } catch (RuntimeException e) {
            path = null;
        }
        if (path == null || path.isBlank() || path.endsWith("/")) {
            return url;   // no filename to shorten to -- keep the full URL
        }
        String name = path.substring(path.lastIndexOf('/') + 1);
        return name.isBlank() ? url : name;
    }

    private void rebuildCategoryItems(Map<FindingTaxonomy.Category, Integer> counts) {
        int total = counts.values().stream().mapToInt(Integer::intValue).sum();
        int keep = catBox.getSelectedIndex();
        rebuildingCatBox = true;
        try {
            catBox.removeAllItems();
            catBox.addItem(counts.isEmpty() ? "All" : "All (" + total + ")");
            for (FindingTaxonomy.Category c : FindingTaxonomy.Category.values()) {
                int n = counts.getOrDefault(c, 0);
                catBox.addItem(counts.isEmpty() ? c.label() : c.label() + " (" + n + ")");
            }
            if (keep >= 0 && keep < catBox.getItemCount()) {
                catBox.setSelectedIndex(keep);
            }
        } finally {
            rebuildingCatBox = false;
        }
    }

    @Override
    protected void onRowSelected(Finding f) {
        if (f == null) {
            viewer.show(null);
            viewer.setSearchExpression("");
            viewer.setInfo(" ");
            return;
        }
        viewer.show(f.getMessages());
        // Jump the Response editor to where this finding actually matched in the JS body.
        viewer.setSearchExpression(f.getRawMatch() == null ? "" : f.getRawMatch());
        StringBuilder sb = new StringBuilder();
        sb.append('[').append(f.getSeverity().name()).append("] ").append(f.getType())
                .append("   |   ").append(f.getLocationUrl());
        if (f.getEvidence() != null && !f.getEvidence().isBlank()) {
            sb.append("   |   ").append(f.getEvidence());
        }
        viewer.setInfo(sb.toString());
    }

    @Override protected HttpRequestResponse rowMessages(Finding f) {
        return f == null ? null : f.getMessages();
    }

    @Override protected boolean supportsBodySearch() { return true; }

    @Override protected String searchableBody(Finding f) {
        return f == null ? null : MessageViewer.toSearchText(f.getMessages());
    }

    @Override protected String rowUrl(Finding f) {
        return f != null && f.getLocationUrl() != null
                && f.getLocationUrl().startsWith("http") ? f.getLocationUrl() : null;
    }

    @Override
    protected void styleCell(Component comp, Finding f, int viewColumn, boolean selected) {
        if (f == null) {
            return;
        }
        if (!selected) {
            comp.setForeground(viewColumn == COL_CATEGORY
                    ? SwingColors.categoryFg(FindingTaxonomy.categoryOf(f.getType()))
                    : SwingColors.severityFg(f.getSeverity()));
        }
        comp.setFont(comp.getFont().deriveFont(viewColumn == 0 ? Font.BOLD : Font.PLAIN));
        if (comp instanceof JComponent jc) {
            String tip = switch (viewColumn) {
                case COL_MATCH -> f.getRawMatch();
                case COL_JS_FILE -> f.getLocationUrl();
                case COL_SEEN -> seen(f, seenPaths, seenParams) == null ? null
                        : "Y = seen in captured traffic, N = only referenced in JS (not yet tested)";
                case COL_EVIDENCE -> evidenceWithHint(f);
                default -> null;
            };
            jc.setToolTipText(tip == null || tip.isBlank() ? null : tip);
        }
    }

    /** Evidence plus the type's generic hint when it carries no {@code Try:} of its own (0.56.0). */
    private static String evidenceWithHint(Finding f) {
        String ev = f.getEvidence() == null ? "" : f.getEvidence();
        String extra = FindingHints.extra(f);
        return extra.isEmpty() ? ev : (ev.isBlank() ? "" : ev + "  |  ") + "Try: " + extra;
    }

    /** Wires cross-tab navigation (JS finding → that file in the JS Assets tab). */
    public void setNavigator(DashboardPanel.Navigator navigator) {
        this.navigator = navigator;
    }

    @Override
    protected void extraMenuItems(javax.swing.JPopupMenu menu, Finding f) {
        if (f == null) {
            return;
        }
        String url = f.getLocationUrl();
        if (navigator != null && url != null && !url.isBlank()) {
            addMenuItem(menu, "Open this JS file in JS Assets", true,
                    () -> navigator.filterJsAssets(url));
        }
        addDeleteHostMenuItem(menu, store, f.getHost());
    }

    /** Findings whose location is a known JS asset URL -- see the class javadoc. Also refreshes the
     * derived per-tick state (library URLs, file risk, seen routes) -- only when a source snapshot
     * changed, so a quiet tick is O(1). */
    @Override
    protected List<Finding> supplyRows() {
        List<JsAsset> assets = store.snapshotJsAssets();
        List<Finding> findings = store.snapshotFindings();
        if (assets != lastAssets || findings != lastFindings) {
            jsRows = jsSourcedFindings(assets, findings);
            Set<String> libs = new HashSet<>();
            for (JsAsset a : assets) {
                if (a.isLibrary() && a.getUrl() != null) {
                    libs.add(a.getUrl());
                }
            }
            libraryUrls = libs;
            lastAssets = assets;
            lastFindings = findings;
        }
        stats = riskMemo.get(findings);
        List<Endpoint> endpoints = store.snapshotEndpoints();
        if (endpoints != lastEndpoints) {
            seenPaths = seenPaths(endpoints);
            lastEndpoints = endpoints;
        }
        List<ParameterInfo> params = store.snapshotParameters();
        if (params != lastParameters) {
            seenParams = seenParams(params);
            lastParameters = params;
        }
        return jsRows;
    }

    /** The JS-sourced subset of findings (a finding whose {@code locationUrl} matches a {@link JsAsset}
     * URL). Package-private + static so it's headlessly testable without constructing the panel (which
     * builds a Montoya {@code MessageViewer} and can't run headless). */
    static List<Finding> jsSourcedFindings(DataStore store) {
        return jsSourcedFindings(store.snapshotJsAssets(), store.snapshotFindings());
    }

    static List<Finding> jsSourcedFindings(List<JsAsset> assets, List<Finding> findings) {
        Set<String> jsUrls = new HashSet<>();
        for (JsAsset a : assets) {
            if (a.getUrl() != null) {
                jsUrls.add(a.getUrl());
            }
        }
        if (jsUrls.isEmpty()) {
            return List.of();
        }
        List<Finding> out = new ArrayList<>();
        for (Finding f : findings) {
            if (jsUrls.contains(f.getLocationUrl())) {
                out.add(f);
            }
        }
        return out;
    }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{80, 100, 220, 240, 45, 220, 65, 260};
    }

    @Override protected Class<?>[] columnClasses() {
        return COLUMN_CLASSES;
    }

    @Override protected Object valueAt(Finding f, int c) {
        return switch (c) {
            case 0 -> f.getSeverity().name();
            case COL_CATEGORY -> FindingTaxonomy.labelOf(f.getType());
            case 2 -> f.getType();
            case COL_MATCH -> f.getRawMatch();
            case COL_SEEN -> {
                Boolean seen = seen(f, seenPaths, seenParams);
                yield seen == null ? "" : seen ? "Y" : "N";
            }
            case COL_JS_FILE -> f.getLocationUrl();
            case COL_RISK -> JsRisk.of(stats, f.getLocationUrl()).score();
            case COL_EVIDENCE -> evidenceWithHint(f);
            default -> "";
        };
    }
}
