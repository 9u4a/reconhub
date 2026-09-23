package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.active.BruteforceEngine;
import com.reconhub.analysis.FindingTaxonomy;
import com.reconhub.analysis.JwtDecoder;
import com.reconhub.analysis.PayloadCheatsheet;
import com.reconhub.core.DataStore;
import com.reconhub.core.Settings;
import com.reconhub.model.Finding;

import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JToggleButton;
import java.awt.Component;
import java.awt.Font;
import java.net.URI;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Findings table with the request/response viewer, a JWT-decode tab, triage, and color-coding. */
public final class FindingsPanel extends AbstractTablePanel<Finding> {

    private static final String[] COLS =
            {"Severity", "Category", "Type", "Evidence", "Location", "Value", "Seen", "Status"};
    private static final int COL_CATEGORY = 1;
    private static final int COL_STATUS = 7;

    private final DataStore store;
    private final Settings settings;
    private final PayloadCheatsheet cheatsheet;
    private final MessageViewer viewer;
    private final JTabbedPane detailTabs = new JTabbedPane();
    private final JTextArea jwtArea = new JTextArea();
    private static final int JWT_TAB = 1;

    /** Severity quick filter; empty = show all. */
    private final Set<Finding.Severity> activeSeverities = EnumSet.noneOf(Finding.Severity.class);
    /** Category filter; null = show all. */
    private FindingTaxonomy.Category activeCategory;
    private final JComboBox<String> catBox = new JComboBox<>();
    private boolean rebuildingCatBox;
    private DashboardPanel.Navigator navigator;
    private BruteforceEngine bruteforce;

    public FindingsPanel(DataStore store, Settings settings, MontoyaApi api,
                         PayloadCheatsheet cheatsheet) {
        super(api);
        this.store = store;
        this.settings = settings;
        this.cheatsheet = cheatsheet;
        this.viewer = new MessageViewer(api);

        jwtArea.setEditable(false);
        jwtArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        jwtArea.setLineWrap(true);
        jwtArea.setWrapStyleWord(true);

        detailTabs.addTab("Message", viewer);
        detailTabs.addTab("JWT", new JScrollPane(jwtArea));
        installDetail(detailTabs, viewer);

        addToToolbar(new JLabel("  Category:"));
        rebuildCategoryItems(Map.of());   // "All" + each category (counts filled on refresh)
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
    }

    // rowIncluded below can hide rows on its own (severity threshold, muted categories, quick-filter
    // toggles) independent of the search box -- the filter must stay installed even with an empty
    // search box, so this MUST stay in sync with rowIncluded (see AbstractTablePanel.hasRowFilter()).
    @Override protected boolean hasRowFilter() { return true; }

    @Override
    protected boolean rowIncluded(Finding f) {
        if (f == null) {
            return true;
        }
        FindingTaxonomy.Category cat = FindingTaxonomy.categoryOf(f.getType());
        // Settings-driven noise control (severity threshold + muted categories).
        if (settings != null && !settings.findingVisible(f.getSeverity(), cat)) {
            return false;
        }
        boolean sevOk = activeSeverities.isEmpty() || activeSeverities.contains(f.getSeverity());
        boolean catOk = activeCategory == null || cat == activeCategory;
        return sevOk && catOk;
    }

    /** Wires cross-tab navigation (finding → related endpoints/parameters). */
    public void setNavigator(DashboardPanel.Navigator navigator) {
        this.navigator = navigator;
    }

    /** Wires the (ACTIVE) known-path bruteforce action for this tab's right-click menu; called once. */
    public void setBruteforce(BruteforceEngine engine) {
        this.bruteforce = engine;
    }

    @Override
    public void refreshData() {
        super.refreshData();
        // Live per-category counts in the filter combo.
        Map<FindingTaxonomy.Category, Integer> counts =
                new EnumMap<>(FindingTaxonomy.Category.class);
        for (Finding f : store.snapshotFindings()) {
            counts.merge(FindingTaxonomy.categoryOf(f.getType()), 1, Integer::sum);
        }
        rebuildCategoryItems(counts);
    }

    /** Rebuilds the category combo items as "Label (count)" while preserving the selection. */
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
            jwtArea.setText("");
            detailTabs.setTitleAt(JWT_TAB, "JWT");
            return;
        }
        updateJwtTab(f);
        viewer.show(f.getMessages());
        StringBuilder sb = new StringBuilder();
        sb.append('[').append(f.getSeverity().name()).append("] ").append(f.getType());
        String value = fullValue(f);
        if (!value.isEmpty()) {
            sb.append("  —  ").append(value);
        }
        sb.append("   |   ").append(f.getLocationUrl())
                .append("   |   seen ").append(f.getTimesSeen());
        if (f.getEvidence() != null && !f.getEvidence().isBlank()) {
            sb.append("   |   ").append(f.getEvidence());
        }
        viewer.setInfo(sb.toString());
    }

    @Override
    protected HttpRequestResponse rowMessages(Finding f) {
        return f == null ? null : f.getMessages();
    }

    @Override protected boolean supportsBodySearch() { return true; }

    @Override
    protected String searchableBody(Finding f) {
        return f == null ? null : MessageViewer.toSearchText(f.getMessages());
    }

    @Override
    protected String rowUrl(Finding f) {
        return f != null && f.getLocationUrl() != null
                && f.getLocationUrl().startsWith("http") ? f.getLocationUrl() : null;
    }

    @Override
    protected void styleCell(Component comp, Finding f, int viewColumn, boolean selected) {
        if (f == null) {
            return;
        }
        Finding.Triage triage = f.getTriage();
        if (!selected) {
            if (triage == Finding.Triage.FALSE_POSITIVE) {
                comp.setForeground(SwingColors.severityFg(Finding.Severity.INFO));
            } else if (viewColumn == COL_CATEGORY) {
                // The Category cell carries its own category color.
                comp.setForeground(SwingColors.categoryFg(FindingTaxonomy.categoryOf(f.getType())));
            } else {
                comp.setForeground(SwingColors.severityFg(f.getSeverity()));
            }
        }
        // Bold the Severity column always; bold the whole row when Confirmed.
        boolean bold = viewColumn == 0 || triage == Finding.Triage.CONFIRMED;
        comp.setFont(comp.getFont().deriveFont(bold ? Font.BOLD : Font.PLAIN));
        // Hover tooltip carries the full, untruncated text so a narrow column hides nothing.
        if (comp instanceof JComponent jc) {
            String tip = switch (viewColumn) {
                case 3 -> f.getEvidence();
                case 4 -> f.getLocationUrl();
                case 5 -> fullValue(f);
                default -> null;
            };
            jc.setToolTipText(tip == null || tip.isBlank() ? null : tip);
        }
    }

    @Override
    protected void extraMenuItems(JPopupMenu menu, Finding f) {
        if (f == null) {
            return;
        }
        String host = hostOf(f.getLocationUrl());
        if (navigator != null && !host.isEmpty()) {
            menu.addSeparator();
            addMenuItem(menu, "View endpoints for " + host, true,
                    () -> navigator.filterEndpoints(host));
            addMenuItem(menu, "View parameters for " + host, true,
                    () -> navigator.filterParameters(host));
        }
        if (cheatsheet != null) {
            PayloadCheatsheet.Set set = cheatsheet.forFindingType(f.getType());
            List<PayloadCheatsheet.Set> suggested = set == null ? List.of() : List.of(set);
            // Always offered, whether or not the finding type auto-matched a class -- e.g. an Auth
            // finding might still be worth an IDOR/SSRF cheatsheet look even with no automatic hit.
            PayloadCheatsheetMenu.addTo(menu, this, cheatsheet, f.getType(), suggested);
        }
        addBruteforceMenuItem(menu, bruteforce, settings, store, host);
        menu.addSeparator();
        for (Finding.Triage t : Finding.Triage.values()) {
            boolean current = f.getTriage() == t;
            addMenuItem(menu, (current ? "● " : "○ ") + "Mark: " + label(t), !current,
                    () -> {
                        f.setTriage(t);
                        store.fireChanged();
                    });
        }
    }

    private static String hostOf(String url) {
        if (url == null || !url.startsWith("http")) {
            return "";
        }
        try {
            String h = URI.create(url).getHost();
            return h == null ? "" : h;
        } catch (RuntimeException e) {
            return "";
        }
    }

    private static String label(Finding.Triage t) {
        return switch (t) {
            case NEW -> "New";
            case REVIEWED -> "Reviewed";
            case CONFIRMED -> "Confirmed";
            case FALSE_POSITIVE -> "False positive";
        };
    }

    /** Populates the JWT tab if the finding carries a JWT (in its value or evidence). */
    private void updateJwtTab(Finding f) {
        String token = JwtDecoder.findFirst(f.getRawMatch());
        if (token == null) {
            token = JwtDecoder.findFirst(f.getEvidence());
        }
        if (token != null) {
            jwtArea.setText(JwtDecoder.decode(token));
            jwtArea.setCaretPosition(0);
            detailTabs.setTitleAt(JWT_TAB, "JWT ✓");
        } else {
            jwtArea.setText("No JWT in this finding.");
            detailTabs.setTitleAt(JWT_TAB, "JWT");
        }
    }

    /** Full (unmasked) matched value for display/copy; empty for non-secret findings. */
    private static String fullValue(Finding f) {
        return f.isSensitive() && f.getRawMatch() != null ? f.getRawMatch() : "";
    }

    @Override protected List<Finding> supplyRows() { return store.snapshotFindings(); }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{80, 95, 200, 240, 240, 240, 50, 90};
    }

    // Seen (6) is numeric -- declared so the sorter compares it as a number, not lexicographically.
    @Override protected Class<?>[] columnClasses() {
        return new Class<?>[]{null, null, null, null, null, null, Integer.class, null};
    }

    @Override protected Object valueAt(Finding f, int c) {
        return switch (c) {
            case 0 -> f.getSeverity().name();
            case COL_CATEGORY -> FindingTaxonomy.labelOf(f.getType());
            case 2 -> f.getType();
            case 3 -> f.getEvidence();
            case 4 -> f.getLocationUrl();
            case 5 -> fullValue(f);
            case 6 -> f.getTimesSeen();
            case COL_STATUS -> label(f.getTriage());
            default -> "";
        };
    }
}
