package com.reconhub.ui;

import com.reconhub.core.DataStore;
import com.reconhub.model.Finding;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.util.EnumMap;
import java.util.Map;

/** Summary dashboard: headline stat cards, findings-by-severity chips, and bar charts. */
public final class DashboardPanel extends JPanel implements Refreshable {

    private static final Color ACCENT = new Color(0x4da3ff);
    private static final Map<Finding.Severity, Color> SEV_COLORS = new EnumMap<>(Finding.Severity.class);
    static {
        SEV_COLORS.put(Finding.Severity.HIGH, new Color(0xff5c5c));
        SEV_COLORS.put(Finding.Severity.MEDIUM, new Color(0xffb020));
        SEV_COLORS.put(Finding.Severity.LOW, new Color(0x4da3ff));
        SEV_COLORS.put(Finding.Severity.INFO, new Color(0x7a8698));
    }

    private final DataStore store;

    private final JLabel requests = stat();
    private final JLabel endpoints = stat();
    private final JLabel parameters = stat();
    private final JLabel findings = stat();
    private final JLabel jsFiles = stat();
    private final JLabel hosts = stat();

    private final JPanel severityRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

    private final BarChartPanel hostChart = new BarChartPanel("Top hosts", 10, ACCENT);
    private final BarChartPanel statusChart = new BarChartPanel("Status codes", 10, ACCENT);
    private final BarChartPanel ctypeChart = new BarChartPanel("Content types", 10, ACCENT);

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

        JPanel charts = new JPanel(new GridLayout(1, 3, 12, 0));
        charts.add(hostChart);
        charts.add(statusChart);
        charts.add(ctypeChart);
        add(new JScrollPane(charts), BorderLayout.CENTER);
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
        t.setForeground(new Color(0x9aa4b2));
        p.add(value);
        p.add(t);
        return p;
    }

    private static JLabel severityChip(Finding.Severity sev, int count) {
        JLabel l = new JLabel(sev.name() + "  " + count);
        Color c = SEV_COLORS.get(sev);
        l.setOpaque(true);
        l.setBackground(new Color(c.getRed(), c.getGreen(), c.getBlue(), 38));
        l.setForeground(c);
        l.setFont(l.getFont().deriveFont(Font.BOLD, 12f));
        l.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(c, 1, true),
                BorderFactory.createEmptyBorder(3, 10, 3, 10)));
        return l;
    }

    @Override
    public void refreshData() {
        requests.setText(String.valueOf(store.getRequestsProcessed()));
        endpoints.setText(String.valueOf(store.snapshotEndpoints().size()));
        parameters.setText(String.valueOf(store.snapshotParameters().size()));
        findings.setText(String.valueOf(store.snapshotFindings().size()));
        jsFiles.setText(String.valueOf(store.snapshotJsAssets().size()));
        hosts.setText(String.valueOf(store.snapshotTech().size()));

        Map<Finding.Severity, Integer> sevCounts = new EnumMap<>(Finding.Severity.class);
        for (Finding f : store.snapshotFindings()) {
            sevCounts.merge(f.getSeverity(), 1, Integer::sum);
        }
        severityRow.removeAll();
        severityRow.add(new JLabel("Findings by severity:"));
        for (Finding.Severity sev : Finding.Severity.values()) {
            severityRow.add(severityChip(sev, sevCounts.getOrDefault(sev, 0)));
        }
        severityRow.revalidate();
        severityRow.repaint();

        hostChart.setData(store.hostCounts());
        statusChart.setData(store.statusCodeCounts());
        ctypeChart.setData(store.contentTypeCounts());
    }
}
