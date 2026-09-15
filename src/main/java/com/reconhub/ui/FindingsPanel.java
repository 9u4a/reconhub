package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.analysis.FindingTaxonomy;
import com.reconhub.analysis.JwtDecoder;
import com.reconhub.core.DataStore;
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
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/** Findings table with the request/response viewer, a JWT-decode tab, triage, and color-coding. */
public final class FindingsPanel extends AbstractTablePanel<Finding> {

    private static final String[] COLS =
            {"Severity", "Category", "Type", "Evidence", "Location", "Value", "Seen", "Status"};
    private static final int COL_CATEGORY = 1;
    private static final int COL_STATUS = 7;

    private final DataStore store;
    private final MessageViewer viewer;
    private final JTabbedPane detailTabs = new JTabbedPane();
    private final JTextArea jwtArea = new JTextArea();
    private static final int JWT_TAB = 1;

    /** Severity quick filter; empty = show all. */
    private final Set<Finding.Severity> activeSeverities = EnumSet.noneOf(Finding.Severity.class);
    /** Category filter; null = show all. */
    private FindingTaxonomy.Category activeCategory;

    public FindingsPanel(DataStore store, MontoyaApi api) {
        super(api);
        this.store = store;
        this.viewer = new MessageViewer(api);

        jwtArea.setEditable(false);
        jwtArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        jwtArea.setLineWrap(true);
        jwtArea.setWrapStyleWord(true);

        detailTabs.addTab("Message", viewer);
        detailTabs.addTab("JWT", new JScrollPane(jwtArea));
        installDetail(detailTabs, viewer);

        addToToolbar(new JLabel("  Category:"));
        JComboBox<String> catBox = new JComboBox<>();
        catBox.addItem("All");
        for (FindingTaxonomy.Category c : FindingTaxonomy.Category.values()) {
            catBox.addItem(c.label());
        }
        catBox.setToolTipText("Show only this finding category");
        catBox.addActionListener(e -> {
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

    @Override
    protected boolean rowIncluded(Finding f) {
        if (f == null) {
            return true;
        }
        boolean sevOk = activeSeverities.isEmpty() || activeSeverities.contains(f.getSeverity());
        boolean catOk = activeCategory == null
                || FindingTaxonomy.categoryOf(f.getType()) == activeCategory;
        return sevOk && catOk;
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
