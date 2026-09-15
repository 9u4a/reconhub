package com.reconhub.ui;

import com.reconhub.analysis.ParameterClassifier;
import com.reconhub.core.DataStore;
import com.reconhub.model.Endpoint;
import com.reconhub.model.Finding;
import com.reconhub.model.ParameterInfo;
import com.reconhub.model.TechInfo;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.Insets;
import java.net.URI;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Summary dashboard: a compact stats strip, findings-by-severity chips, and aggregate triage views —
 * a per-host scorecard (host list + per-host detail), top finding types, notable endpoints (risky
 * params / admin paths), a Top-hosts chart, and a parameter-class summary. All read-only aggregates
 * over the {@link DataStore}. Laid out to stay legible at half width (strips wrap; scorecard splits).
 */
public final class DashboardPanel extends JPanel implements Refreshable {

    private static final Color ACCENT = new Color(0x4da3ff);
    private static final Color MUTED = new Color(0x9aa4b2);
    private static final Color LINE = new Color(0x2a313b);
    private static final Map<Finding.Severity, Color> SEV_COLORS = new EnumMap<>(Finding.Severity.class);
    static {
        SEV_COLORS.put(Finding.Severity.HIGH, new Color(0xff5c5c));
        SEV_COLORS.put(Finding.Severity.MEDIUM, new Color(0xffb020));
        SEV_COLORS.put(Finding.Severity.LOW, new Color(0x4da3ff));
        SEV_COLORS.put(Finding.Severity.INFO, new Color(0x7a8698));
    }
    /** Param-name classes considered high-risk for the "Notable endpoints" list. */
    private static final Set<String> RISKY_CLASSES =
            Set.of("IDOR", "Redirect/SSRF", "File/Path", "SQLi/Sort", "Command", "Secret/Token");

    private final DataStore store;

    private final JLabel requests = stat();
    private final JLabel endpoints = stat();
    private final JLabel parameters = stat();
    private final JLabel findings = stat();
    private final JLabel jsFiles = stat();
    private final JLabel hosts = stat();

    private final JPanel severityRow = new JPanel(new WrapLayout(FlowLayout.LEFT, 6, 4));
    private final BarChartPanel hostChart = new BarChartPanel("", 8, ACCENT);
    private final JPanel classChips = new JPanel(new WrapLayout(FlowLayout.LEFT, 6, 4));

    // Host scorecard: the visible table carries only Host/Endpoints/Params; the full per-host
    // counts live in hostStats and drive the detail panel on selection.
    private final SimpleModel hostModel = new SimpleModel(
            new String[]{"Host", "Endpoints", "Params"},
            new Class<?>[]{String.class, Integer.class, Integer.class});
    private final Map<String, int[]> hostStats = new HashMap<>();   // label -> [ep,param,H,M,L,I,missHdr]
    private final JPanel hostDetail = new JPanel(new BorderLayout());
    private String selectedHost;

    private final SimpleModel typeModel = new SimpleModel(
            new String[]{"Finding type", "Count"},
            new Class<?>[]{String.class, Integer.class});
    private final SimpleModel notableModel = new SimpleModel(
            new String[]{"Method", "URL", "Why"},
            new Class<?>[]{String.class, String.class, String.class});

    private final JTable hostTable = new JTable(hostModel);
    private final JTable typeTable = new JTable(typeModel);
    private final JTable notableTable = new JTable(notableModel);

    public DashboardPanel(DataStore store) {
        this.store = store;
        setLayout(new BorderLayout(0, 14));
        setBorder(BorderFactory.createEmptyBorder(14, 16, 14, 16));

        // --- compact top strip: small stat pills + severity chips (both wrap at narrow width) ---
        JPanel north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));

        JPanel pills = new JPanel(new WrapLayout(FlowLayout.LEFT, 6, 4));
        pills.setAlignmentX(LEFT_ALIGNMENT);
        pills.add(pill("Requests", requests));
        pills.add(pill("Endpoints", endpoints));
        pills.add(pill("Parameters", parameters));
        pills.add(pill("Findings", findings));
        pills.add(pill("JS files", jsFiles));
        pills.add(pill("Hosts", hosts));
        north.add(pills);

        severityRow.setAlignmentX(LEFT_ALIGNMENT);
        severityRow.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));
        north.add(severityRow);
        add(north, BorderLayout.NORTH);

        configureTables();

        JPanel body = new JPanel();
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));

        // Host scorecard: list on the left, per-host severity/header detail on the right.
        hostDetail.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
        JSplitPane scorecard = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(hostTable), new JScrollPane(hostDetail));
        scorecard.setResizeWeight(0.62);
        scorecard.setBorder(null);
        scorecard.setContinuousLayout(true);
        body.add(sized(titled("Host scorecard", scorecard), 250));
        body.add(Box.createVerticalStrut(14));

        JPanel row2 = new JPanel(new GridLayout(1, 2, 14, 0));
        row2.add(titled("Top findings", new JScrollPane(typeTable)));
        row2.add(titled("Notable endpoints  (risky params / admin·api paths)",
                new JScrollPane(notableTable)));
        body.add(sized(row2, 230));
        body.add(Box.createVerticalStrut(14));

        JPanel row3 = new JPanel(new GridLayout(1, 2, 14, 0));
        row3.add(titled("Top hosts", hostChart));
        row3.add(titled("Parameter classes", classChips));
        body.add(sized(row3, 250));
        body.add(Box.createVerticalGlue());

        add(new JScrollPane(body), BorderLayout.CENTER);
        updateHostDetail(null);
    }

    private void configureTables() {
        styleTable(hostTable);
        styleTable(typeTable);
        styleTable(notableTable);
        int[] hw = {220, 90, 90};
        for (int i = 0; i < hw.length; i++) {
            hostTable.getColumnModel().getColumn(i).setPreferredWidth(hw[i]);
        }
        hostTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        hostTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int view = hostTable.getSelectedRow();
            if (view < 0) {
                return;
            }
            int model = hostTable.convertRowIndexToModel(view);
            updateHostDetail((String) hostModel.getValueAt(model, 0));
        });
        typeTable.getColumnModel().getColumn(1).setMaxWidth(90);
    }

    // ---- refresh --------------------------------------------------------

    @Override
    public void refreshData() {
        List<Endpoint> eps = store.snapshotEndpoints();
        List<ParameterInfo> params = store.snapshotParameters();
        List<Finding> finds = store.snapshotFindings();

        requests.setText(String.valueOf(store.getRequestsProcessed()));
        endpoints.setText(String.valueOf(eps.size()));
        parameters.setText(String.valueOf(params.size()));
        findings.setText(String.valueOf(finds.size()));
        jsFiles.setText(String.valueOf(store.snapshotJsAssets().size()));
        hosts.setText(String.valueOf(store.snapshotTech().size()));

        Map<Finding.Severity, Integer> sevCounts = new EnumMap<>(Finding.Severity.class);
        for (Finding f : finds) {
            sevCounts.merge(f.getSeverity(), 1, Integer::sum);
        }
        severityRow.removeAll();
        severityRow.add(muted("Findings by severity:"));
        for (Finding.Severity sev : Finding.Severity.values()) {
            severityRow.add(chip(sev.name() + "  " + sevCounts.getOrDefault(sev, 0), SEV_COLORS.get(sev)));
        }
        severityRow.revalidate();
        severityRow.repaint();

        hostChart.setData(store.hostCounts());
        buildHostScorecard(eps, params, finds);
        buildTopFindings(finds);
        buildNotableEndpoints(eps);
        buildClassSummary(params);
    }

    private void buildHostScorecard(List<Endpoint> eps, List<ParameterInfo> params,
                                    List<Finding> finds) {
        Map<String, int[]> byHost = new TreeMap<>();   // [ep, param, H, M, L, I, missHdr]
        for (Endpoint e : eps) {
            row(byHost, hostLabel(e.getHost()))[0]++;
        }
        for (ParameterInfo p : params) {
            row(byHost, hostLabel(p.getHost()))[1]++;
        }
        for (Finding f : finds) {
            int idx = 2 + f.getSeverity().ordinal();   // HIGH..INFO -> 2..5
            row(byHost, hostLabel(hostOf(f.getLocationUrl())))[idx]++;
        }
        for (TechInfo t : store.snapshotTech()) {
            row(byHost, hostLabel(t.getHost()))[6] = t.getMissingSecurityHeaders().size();
        }

        hostStats.clear();
        hostStats.putAll(byHost);

        List<Object[]> rows = new ArrayList<>();
        for (Map.Entry<String, int[]> e : byHost.entrySet()) {
            int[] c = e.getValue();
            rows.add(new Object[]{e.getKey(), c[0], c[1],
                    // hidden sort weight so the most interesting host lands on top
                    c[2] * 100 + c[3] * 10 + c[4]});
        }
        // Most findings first (H weighted), then most endpoints.
        rows.sort(Comparator
                .comparingInt((Object[] r) -> (int) r[3]).reversed()
                .thenComparing(r -> (int) r[1], Comparator.reverseOrder()));
        List<Object[]> trimmed = new ArrayList<>();
        for (Object[] r : rows) {
            trimmed.add(new Object[]{r[0], r[1], r[2]});   // drop sort key
        }
        hostModel.setRows(trimmed);

        // Preserve the selected host across refreshes; otherwise show the top host.
        String want = selectedHost != null && hostStats.containsKey(selectedHost)
                ? selectedHost
                : (trimmed.isEmpty() ? null : (String) trimmed.get(0)[0]);
        if (want == null) {
            updateHostDetail(null);
        } else {
            selectRow(want);
        }
    }

    private void selectRow(String host) {
        for (int i = 0; i < hostModel.getRowCount(); i++) {
            if (host.equals(hostModel.getValueAt(i, 0))) {
                int view = hostTable.convertRowIndexToView(i);
                if (view >= 0) {
                    hostTable.getSelectionModel().setSelectionInterval(view, view);
                }
                break;
            }
        }
        updateHostDetail(host);
    }

    /** Rebuilds the right-hand detail card for one host (severity breakdown + missing headers). */
    private void updateHostDetail(String host) {
        selectedHost = host;
        hostDetail.removeAll();
        int[] c = host == null ? null : hostStats.get(host);
        if (c == null) {
            JLabel hint = muted("Select a host on the left to see its severity breakdown.");
            hint.setBorder(BorderFactory.createEmptyBorder(6, 4, 0, 0));
            hostDetail.add(hint, BorderLayout.NORTH);
            hostDetail.revalidate();
            hostDetail.repaint();
            return;
        }

        JLabel header = new JLabel(host);
        header.setFont(header.getFont().deriveFont(Font.BOLD, 14f));
        header.setBorder(BorderFactory.createEmptyBorder(2, 2, 8, 2));

        JPanel grid = new JPanel(new GridLayout(0, 2, 10, 6));
        grid.setOpaque(false);
        grid.add(metric("Endpoints", c[0], null));
        grid.add(metric("Parameters", c[1], null));
        grid.add(metric("High", c[2], SEV_COLORS.get(Finding.Severity.HIGH)));
        grid.add(metric("Medium", c[3], SEV_COLORS.get(Finding.Severity.MEDIUM)));
        grid.add(metric("Low", c[4], SEV_COLORS.get(Finding.Severity.LOW)));
        grid.add(metric("Info", c[5], SEV_COLORS.get(Finding.Severity.INFO)));
        grid.add(metric("Missing headers", c[6],
                c[6] > 0 ? SEV_COLORS.get(Finding.Severity.MEDIUM) : null));

        JPanel wrap = new JPanel(new BorderLayout());
        wrap.setOpaque(false);
        wrap.add(header, BorderLayout.NORTH);
        wrap.add(grid, BorderLayout.CENTER);
        hostDetail.add(wrap, BorderLayout.NORTH);
        hostDetail.revalidate();
        hostDetail.repaint();
    }

    /** A single "label: value" tile for the host-detail card; value is colored when non-zero. */
    private static JPanel metric(String label, int value, Color valueColor) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(LINE),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)));
        JLabel t = new JLabel(label.toUpperCase());
        t.setFont(t.getFont().deriveFont(10.5f));
        t.setForeground(MUTED);
        JLabel v = new JLabel(String.valueOf(value));
        v.setFont(v.getFont().deriveFont(Font.BOLD, 16f));
        if (valueColor != null && value > 0) {
            v.setForeground(valueColor);
        }
        p.add(t, BorderLayout.NORTH);
        p.add(v, BorderLayout.CENTER);
        return p;
    }

    private void buildTopFindings(List<Finding> finds) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (Finding f : finds) {
            counts.merge(f.getType(), 1, Integer::sum);
        }
        List<Object[]> rows = new ArrayList<>();
        counts.forEach((type, n) -> rows.add(new Object[]{type, n}));
        rows.sort(Comparator.comparingInt((Object[] r) -> (int) r[1]).reversed());
        typeModel.setRows(rows);
    }

    private void buildNotableEndpoints(List<Endpoint> eps) {
        List<Object[]> rows = new ArrayList<>();
        for (Endpoint e : eps) {
            java.util.TreeSet<String> risky = new java.util.TreeSet<>();
            for (String name : e.getParamNames()) {
                for (String cls : ParameterClassifier.classify(name)) {
                    if (RISKY_CLASSES.contains(cls)) {
                        risky.add(cls);
                    }
                }
            }
            String pathNote = pathNote(e);
            if (risky.isEmpty() && pathNote == null) {
                continue;
            }
            StringBuilder why = new StringBuilder(String.join(", ", risky));
            if (pathNote != null) {
                if (why.length() > 0) {
                    why.append("; ");
                }
                why.append(pathNote);
            }
            rows.add(new Object[]{e.getMethod(), e.getNormalizedUrl(), why.toString(), risky.size()});
        }
        rows.sort(Comparator.comparingInt((Object[] r) -> (int) r[3]).reversed());
        List<Object[]> trimmed = new ArrayList<>();
        for (Object[] r : rows) {
            trimmed.add(new Object[]{r[0], r[1], r[2]});   // drop sort key
            if (trimmed.size() >= 60) {
                break;
            }
        }
        notableModel.setRows(trimmed);
    }

    private void buildClassSummary(List<ParameterInfo> params) {
        Map<String, Integer> counts = new TreeMap<>();
        for (ParameterInfo p : params) {
            for (String cls : ParameterClassifier.classify(p.getName())) {
                counts.merge(cls, 1, Integer::sum);
            }
        }
        classChips.removeAll();
        if (counts.isEmpty()) {
            classChips.add(muted("None"));
        } else {
            counts.forEach((cls, n) -> classChips.add(chip(cls + "  " + n, ACCENT)));
        }
        classChips.revalidate();
        classChips.repaint();
    }

    // ---- helpers --------------------------------------------------------

    private static int[] row(Map<String, int[]> m, String host) {
        return m.computeIfAbsent(host, k -> new int[7]);
    }

    private static String hostLabel(String host) {
        return host == null || host.isBlank() ? "(relative / JS)" : host;
    }

    private static String hostOf(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }
        try {
            URI u = URI.create(url);
            if (u.getHost() != null) {
                return u.getHost();
            }
        } catch (RuntimeException ignored) {
            // non-URL location
        }
        return "";
    }

    private static String pathNote(Endpoint e) {
        String p = (e.getPath() == null ? "" : e.getPath()).toLowerCase(Locale.ROOT);
        if (p.contains("admin")) {
            return "admin path";
        }
        if (p.contains("graphql")) {
            return "graphql";
        }
        if (p.contains("actuator")) {
            return "actuator";
        }
        if (p.contains("internal")) {
            return "internal path";
        }
        if (p.contains("/api") || p.contains("swagger") || p.contains("api-docs")) {
            return "api";
        }
        return null;
    }

    private static JLabel stat() {
        JLabel l = new JLabel("0");
        l.setFont(l.getFont().deriveFont(Font.BOLD, 16f));
        return l;
    }

    /** Compact "LABEL value" pill for the top strip. */
    private JPanel pill(String title, JLabel value) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(LINE),
                BorderFactory.createEmptyBorder(1, 8, 1, 10)));
        JLabel t = new JLabel(title.toUpperCase());
        t.setFont(t.getFont().deriveFont(10.5f));
        t.setForeground(MUTED);
        p.add(t);
        p.add(value);
        return p;
    }

    private static JLabel chip(String text, Color c) {
        JLabel l = new JLabel(text);
        l.setOpaque(true);
        l.setBackground(new Color(c.getRed(), c.getGreen(), c.getBlue(), 38));
        l.setForeground(c);
        l.setFont(l.getFont().deriveFont(Font.BOLD, 12f));
        l.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(c, 1, true),
                BorderFactory.createEmptyBorder(3, 10, 3, 10)));
        return l;
    }

    private static JLabel muted(String text) {
        JLabel l = new JLabel(text);
        l.setForeground(MUTED);
        return l;
    }

    private static void styleTable(JTable t) {
        t.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        t.setRowSorter(new TableRowSorter<>(t.getModel()));
        t.setRowHeight(24);
        t.setShowGrid(false);
        t.setIntercellSpacing(new Dimension(0, 0));
        t.getTableHeader().setFont(t.getFont().deriveFont(Font.BOLD, 12.5f));
        t.getTableHeader().setReorderingAllowed(false);
        t.setFont(t.getFont().deriveFont(13f));
    }

    private static JPanel titled(String title, Component inner) {
        JPanel p = new JPanel(new BorderLayout());
        javax.swing.border.TitledBorder tb = BorderFactory.createTitledBorder(title);
        tb.setTitleFont(p.getFont().deriveFont(Font.BOLD, 15f));
        p.setBorder(BorderFactory.createCompoundBorder(tb,
                BorderFactory.createEmptyBorder(6, 8, 8, 8)));
        p.add(inner, BorderLayout.CENTER);
        return p;
    }

    private static JPanel sized(JPanel p, int height) {
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, height));
        p.setPreferredSize(new Dimension(p.getPreferredSize().width, height));
        p.setAlignmentX(LEFT_ALIGNMENT);
        return p;
    }

    // ---- read-only aggregate table model --------------------------------

    private static final class SimpleModel extends AbstractTableModel {
        private final String[] cols;
        private final Class<?>[] types;
        private List<Object[]> rows = new ArrayList<>();

        SimpleModel(String[] cols, Class<?>[] types) {
            this.cols = cols;
            this.types = types;
        }

        void setRows(List<Object[]> r) {
            this.rows = r != null ? r : new ArrayList<>();
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return cols.length; }
        @Override public String getColumnName(int c) { return cols[c]; }
        @Override public Class<?> getColumnClass(int c) { return types[c]; }
        @Override public boolean isCellEditable(int r, int c) { return false; }
        @Override public Object getValueAt(int r, int c) { return rows.get(r)[c]; }
    }

    /**
     * A {@link FlowLayout} that wraps to multiple rows and reports the correct height for the parent
     * width, so the top stat/chip strips stay fully visible when the panel is only half wide.
     */
    private static final class WrapLayout extends FlowLayout {
        WrapLayout(int align, int hgap, int vgap) {
            super(align, hgap, vgap);
        }

        @Override public Dimension preferredLayoutSize(Container target) { return layoutSize(target, true); }
        @Override public Dimension minimumLayoutSize(Container target) {
            Dimension d = layoutSize(target, false);
            d.width -= (getHgap() + 1);
            return d;
        }

        private Dimension layoutSize(Container target, boolean preferred) {
            synchronized (target.getTreeLock()) {
                int targetWidth = target.getSize().width;
                if (targetWidth == 0) {
                    targetWidth = Integer.MAX_VALUE;
                }
                Insets insets = target.getInsets();
                int maxWidth = targetWidth - (insets.left + insets.right + getHgap() * 2);
                Dimension dim = new Dimension(0, 0);
                int rowWidth = 0;
                int rowHeight = 0;
                for (int i = 0; i < target.getComponentCount(); i++) {
                    Component m = target.getComponent(i);
                    if (!m.isVisible()) {
                        continue;
                    }
                    Dimension d = preferred ? m.getPreferredSize() : m.getMinimumSize();
                    if (rowWidth + d.width > maxWidth && rowWidth > 0) {
                        dim.width = Math.max(dim.width, rowWidth);
                        dim.height += rowHeight + getVgap();
                        rowWidth = 0;
                        rowHeight = 0;
                    }
                    rowWidth += d.width + getHgap();
                    rowHeight = Math.max(rowHeight, d.height);
                }
                dim.width = Math.max(dim.width, rowWidth);
                dim.height += rowHeight;
                dim.width += insets.left + insets.right + getHgap() * 2;
                dim.height += insets.top + insets.bottom + getVgap() * 2;
                return dim;
            }
        }
    }
}
