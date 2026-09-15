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
import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.net.URI;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Summary dashboard: headline cards, findings-by-severity chips, a Top-hosts chart, and aggregate
 * triage views — a per-host scorecard, top finding types, notable endpoints (risky params / admin
 * paths), and a parameter-class summary. All read-only aggregates over the {@link DataStore}.
 */
public final class DashboardPanel extends JPanel implements Refreshable {

    private static final Color ACCENT = new Color(0x4da3ff);
    private static final Color MUTED = new Color(0x9aa4b2);
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

    private final JPanel severityRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
    private final BarChartPanel hostChart = new BarChartPanel("Top hosts", 10, ACCENT);
    private final JPanel classChips = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));

    private final SimpleModel hostModel = new SimpleModel(
            new String[]{"Host", "Endpoints", "Params", "H", "M", "L", "I", "Miss hdr"},
            new Class<?>[]{String.class, Integer.class, Integer.class, Integer.class,
                    Integer.class, Integer.class, Integer.class, Integer.class});
    private final SimpleModel typeModel = new SimpleModel(
            new String[]{"Finding type", "Count"},
            new Class<?>[]{String.class, Integer.class});
    private final SimpleModel notableModel = new SimpleModel(
            new String[]{"Method", "URL", "Why"},
            new Class<?>[]{String.class, String.class, String.class});

    public DashboardPanel(DataStore store) {
        this.store = store;
        setLayout(new BorderLayout(0, 10));
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));

        JPanel cards = new JPanel(new GridLayout(1, 6, 10, 10));
        cards.add(card("Requests", requests));
        cards.add(card("Endpoints", endpoints));
        cards.add(card("Parameters", parameters));
        cards.add(card("Findings", findings));
        cards.add(card("JS files", jsFiles));
        cards.add(card("Hosts", hosts));
        cards.setAlignmentX(LEFT_ALIGNMENT);
        north.add(cards);

        severityRow.setAlignmentX(LEFT_ALIGNMENT);
        north.add(severityRow);
        add(north, BorderLayout.NORTH);

        JPanel body = new JPanel();
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));

        JPanel row1 = new JPanel(new GridLayout(1, 2, 12, 0));
        row1.add(hostChart);
        row1.add(titled("Parameter classes", classChips));
        body.add(sized(row1, 210));

        body.add(sized(titled("Host scorecard", table(hostModel)), 200));

        JPanel row2 = new JPanel(new GridLayout(1, 2, 12, 0));
        row2.add(titled("Top findings", table(typeModel)));
        row2.add(titled("Notable endpoints (risky params / admin paths)", table(notableModel)));
        body.add(sized(row2, 220));
        body.add(Box.createVerticalGlue());

        add(new JScrollPane(body), BorderLayout.CENTER);
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
        severityRow.add(new JLabel("Findings by severity:"));
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

        List<Object[]> rows = new ArrayList<>();
        for (Map.Entry<String, int[]> e : byHost.entrySet()) {
            int[] c = e.getValue();
            rows.add(new Object[]{e.getKey(), c[0], c[1], c[2], c[3], c[4], c[5], c[6]});
        }
        // Most findings first (H weighted), then most endpoints.
        rows.sort(Comparator
                .comparingInt((Object[] r) -> (int) r[3] * 100 + (int) r[4] * 10 + (int) r[5]).reversed()
                .thenComparing(r -> (int) r[1], Comparator.reverseOrder()));
        hostModel.setRows(rows);
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
        l.setFont(l.getFont().deriveFont(Font.BOLD, 26f));
        return l;
    }

    private JPanel card(String title, JLabel value) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0x2a313b)),
                BorderFactory.createEmptyBorder(10, 14, 10, 14)));
        p.setPreferredSize(new Dimension(150, 76));
        JLabel t = new JLabel(title.toUpperCase());
        t.setFont(t.getFont().deriveFont(11f));
        t.setForeground(MUTED);
        p.add(value);
        p.add(t);
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

    private static JScrollPane table(SimpleModel model) {
        JTable t = new JTable(model);
        t.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        t.setRowSorter(new TableRowSorter<>(model));
        return new JScrollPane(t);
    }

    private static JPanel titled(String title, java.awt.Component inner) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createTitledBorder(title));
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
}
