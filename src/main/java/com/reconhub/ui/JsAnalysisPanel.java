package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.analysis.FindingTaxonomy;
import com.reconhub.core.Bookmarks;
import com.reconhub.core.DataStore;
import com.reconhub.core.Hosts;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;

import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JToggleButton;
import java.awt.Component;
import java.awt.Font;
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

    private static final String[] COLS = {"Severity", "Category", "Type", "JS File", "Evidence"};
    private static final int COL_CATEGORY = 1;

    private final DataStore store;
    private final MessageViewer viewer;

    private final Set<Finding.Severity> activeSeverities = EnumSet.noneOf(Finding.Severity.class);
    private FindingTaxonomy.Category activeCategory;
    private final JComboBox<String> catBox = new JComboBox<>();
    private boolean rebuildingCatBox;
    private final ColumnValueFilter<Finding> hostFilter =
            new ColumnValueFilter<>("Host", f -> Hosts.label(f.getHost()));

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
            reapplyFilter();
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
                reapplyFilter();
            });
            addToToolbar(b);
        }

        hostFilter.setOnChange(this::reapplyFilter);
        addToToolbar(hostFilter.component());
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
        return sevOk && catOk && hostFilter.test(f);
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
            viewer.setInfo(" ");
            return;
        }
        viewer.show(f.getMessages());
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
                case 3 -> f.getLocationUrl();
                case 4 -> f.getEvidence();
                default -> null;
            };
            jc.setToolTipText(tip == null || tip.isBlank() ? null : tip);
        }
    }

    @Override
    protected void extraMenuItems(javax.swing.JPopupMenu menu, Finding f) {
        if (f == null) {
            return;
        }
        addDeleteHostMenuItem(menu, store, f.getHost());
    }

    /** Findings whose location is a known JS asset URL -- see the class javadoc. */
    @Override
    protected List<Finding> supplyRows() {
        return jsSourcedFindings(store);
    }

    /** The JS-sourced subset of findings (a finding whose {@code locationUrl} matches a {@link JsAsset}
     * URL). Package-private + static so it's headlessly testable without constructing the panel (which
     * builds a Montoya {@code MessageViewer} and can't run headless). */
    static List<Finding> jsSourcedFindings(DataStore store) {
        Set<String> jsUrls = new HashSet<>();
        for (JsAsset a : store.snapshotJsAssets()) {
            if (a.getUrl() != null) {
                jsUrls.add(a.getUrl());
            }
        }
        if (jsUrls.isEmpty()) {
            return List.of();
        }
        List<Finding> out = new ArrayList<>();
        for (Finding f : store.snapshotFindings()) {
            if (jsUrls.contains(f.getLocationUrl())) {
                out.add(f);
            }
        }
        return out;
    }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{80, 100, 220, 260, 300};
    }

    @Override protected Object valueAt(Finding f, int c) {
        return switch (c) {
            case 0 -> f.getSeverity().name();
            case COL_CATEGORY -> FindingTaxonomy.labelOf(f.getType());
            case 2 -> f.getType();
            case 3 -> f.getLocationUrl();
            case 4 -> f.getEvidence();
            default -> "";
        };
    }
}
