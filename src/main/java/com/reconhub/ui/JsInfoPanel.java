package com.reconhub.ui;

import com.reconhub.model.Finding;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * JS Assets detail (0.63.0): a header (file name, URL, badges, action buttons) above tabs of sortable tables
 * -- Findings, Client Flows, Notes, Endpoints, File -- plus any tab the owner adds (Response). Tab titles
 * carry counts; the selected tab is kept when another file is selected. Data comes from {@link JsInfoContent}.
 */
final class JsInfoPanel extends JPanel {

    static final int FINDINGS = 0;
    static final int FLOWS = 1;
    static final int NOTES = 2;
    static final int ENDPOINTS = 3;
    static final int FILE = 4;

    private final JLabel title = new JLabel(" ");
    private final JLabel url = new JLabel(" ");
    private final JPanel badges = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
    private final JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
    private final JLabel libNote = new JLabel(" ");
    private final JTabbedPane tabs = new JTabbedPane();

    private final Table<JsInfoContent.FindingRow> findings = new Table<>(
            new String[]{"Severity", "Finding", "Value", "Try"}, new int[]{80, 280, 200, 460},
            r -> new Object[]{r.severity().name(), r.type(), r.value(), r.hint()});
    private final Table<JsInfoContent.FlowRow> flows = new Table<>(
            new String[]{"Method", "Path", "Body keys", "Auth", "Trigger", "Function"}, new int[]{70, 280, 160, 180, 160, 120},
            r -> new Object[]{r.method(), r.path(), r.bodyKeys(), r.auth(), r.trigger(), r.function()});
    private final Table<JsInfoContent.NoteRow> notes = new Table<>(
            new String[]{"Kind", "Detail", "Try"}, new int[]{170, 480, 340},
            r -> new Object[]{r.kind(), r.detail(), r.hint()});
    private final Table<String> endpoints = new Table<>(new String[]{"URL"}, new int[]{900}, r -> new Object[]{r});
    private final Table<String[]> file = new Table<>(new String[]{"Field", "Value"}, new int[]{110, 800},
            r -> new Object[]{r[0], r[1]});

    JsInfoPanel() {
        super(new BorderLayout());
        title.setFont(title.getFont().deriveFont(Font.BOLD, title.getFont().getSize2D() + 4f));
        url.setForeground(SwingColors.MUTED);
        libNote.setForeground(SwingColors.WARN);
        badges.setOpaque(false);
        actions.setOpaque(false);

        JPanel head = new JPanel();
        head.setLayout(new BoxLayout(head, BoxLayout.Y_AXIS));
        head.setBorder(BorderFactory.createEmptyBorder(8, 10, 6, 10));
        JPanel row1 = new JPanel(new BorderLayout());
        row1.add(title, BorderLayout.WEST);
        row1.add(actions, BorderLayout.EAST);
        JPanel row2 = new JPanel(new BorderLayout());
        row2.add(url, BorderLayout.WEST);
        JPanel row3 = new JPanel(new BorderLayout());
        row3.add(badges, BorderLayout.WEST);
        row3.add(libNote, BorderLayout.CENTER);
        for (JPanel r : List.of(row1, row2, row3)) {
            r.setAlignmentX(Component.LEFT_ALIGNMENT);
            head.add(r);
        }

        findings.table.setDefaultRenderer(Object.class, new Renderer(0, true));
        flows.table.setDefaultRenderer(Object.class, new Renderer(0, false));
        notes.table.setDefaultRenderer(Object.class, new Renderer(-1, false));
        tabs.addTab("Findings", findings.scroll);
        tabs.addTab("Client Flows", flows.scroll);
        tabs.addTab("Notes", notes.scroll);
        tabs.addTab("Endpoints", endpoints.scroll);
        tabs.addTab("File", file.scroll);
        tabs.setToolTipTextAt(NOTES, "Matches the analysis could not prove -- for manual review, not findings");

        add(head, BorderLayout.NORTH);
        add(tabs, BorderLayout.CENTER);
    }

    /** Adds a button / control to the header's right side. */
    void addAction(Component c) {
        actions.add(c);
    }

    JTabbedPane tabs() {
        return tabs;
    }

    void show(JsInfoContent.Content c) {
        title.setText(c.title());
        url.setText(c.url());
        url.setToolTipText(c.url());
        libNote.setText(c.libraryNote().isEmpty() ? " " : "   " + c.libraryNote());
        badges.removeAll();
        for (JsInfoContent.Badge b : c.badges()) badges.add(badge(b));
        badges.revalidate();
        badges.repaint();
        findings.set(c.findings());
        flows.set(c.flows());
        notes.set(c.notes());
        endpoints.set(c.endpoints());
        file.set(c.file());
        tabs.setTitleAt(FINDINGS, "Findings (" + c.findings().size() + ")");
        tabs.setTitleAt(FLOWS, "Client Flows (" + c.flows().size() + ")");
        tabs.setTitleAt(NOTES, "Notes (" + c.notes().size() + ")");
        tabs.setTitleAt(ENDPOINTS, "Endpoints (" + c.endpoints().size() + ")");
    }

    void clear() {
        title.setText(" ");
        url.setText(" ");
        libNote.setText(" ");
        badges.removeAll();
        badges.repaint();
        findings.set(List.of());
        flows.set(List.of());
        notes.set(List.of());
        endpoints.set(List.of());
        file.set(List.of());
        tabs.setTitleAt(FINDINGS, "Findings");
        tabs.setTitleAt(FLOWS, "Client Flows");
        tabs.setTitleAt(NOTES, "Notes");
        tabs.setTitleAt(ENDPOINTS, "Endpoints");
    }

    private static JLabel badge(JsInfoContent.Badge b) {
        JLabel l = new JLabel(b.text());
        Color base = l.getBackground() == null ? Color.WHITE : l.getBackground();
        Color tint = b.warn() ? SwingColors.WARN : SwingColors.ACCENT;
        l.setOpaque(true);
        l.setBackground(SwingColors.blend(base, tint, 0.22));
        if (b.warn()) {
            l.setForeground(SwingColors.WARN);
            l.setFont(l.getFont().deriveFont(Font.BOLD));
        }
        l.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
        return l;
    }

    // ---- table helper ------------------------------------------------------------------------

    /** Read-only, sortable table over a row list; full cell text as tooltip; Ctrl+C copies rows. */
    static final class Table<R> {
        final JTable table;
        final JScrollPane scroll;
        private final Model model;

        Table(String[] cols, int[] widths, Function<R, Object[]> cells) {
            this.model = new Model(cols, cells);
            this.table = new JTable(model);
            table.setAutoCreateRowSorter(true);
            table.setRowHeight(22);
            table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            table.setFillsViewportHeight(true);
            for (int i = 0; i < widths.length; i++) table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
            this.scroll = new JScrollPane(table);
        }

        void set(List<R> rows) {
            model.rows = new ArrayList<>(rows);
            model.fireTableDataChanged();
        }

        int rowCount() {
            return model.rows.size();
        }

        Object valueAt(int row, int col) {
            return model.getValueAt(row, col);
        }

        private final class Model extends AbstractTableModel {
            private final String[] cols;
            private final Function<R, Object[]> cells;
            List<R> rows = List.of();

            Model(String[] cols, Function<R, Object[]> cells) {
                this.cols = cols;
                this.cells = cells;
            }

            @Override public int getRowCount() { return rows.size(); }
            @Override public int getColumnCount() { return cols.length; }
            @Override public String getColumnName(int c) { return cols[c]; }
            @Override public Object getValueAt(int r, int c) { return cells.apply(rows.get(r))[c]; }
        }
    }

    /** Colors the severity / method column; "Try" columns muted-green italic; tooltips = full text. */
    private static final class Renderer extends DefaultTableCellRenderer {
        private final int colorCol;
        private final boolean severity;

        Renderer(int colorCol, boolean severity) {
            this.colorCol = colorCol;
            this.severity = severity;
        }

        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int row, int col) {
            Component c = super.getTableCellRendererComponent(t, v, sel, focus, row, col);
            int mc = t.convertColumnIndexToModel(col);
            String name = t.getModel().getColumnName(mc);
            c.setFont(t.getFont());
            if (!sel) c.setForeground(t.getForeground());
            if (!sel && mc == colorCol && v != null) {
                c.setForeground(severity ? severityColor(String.valueOf(v)) : methodColor(String.valueOf(v)));
                c.setFont(t.getFont().deriveFont(Font.BOLD));
            } else if (!sel && "Try".equals(name)) {
                c.setForeground(SwingColors.OK);
            }
            if (c instanceof JComponent jc) {
                String s = v == null ? "" : String.valueOf(v);
                jc.setToolTipText(s.length() > 40 ? s : null);
            }
            return c;
        }

        static Color methodColor(String method) {
            return switch (method) {
                case "DELETE" -> SwingColors.HIGH;
                case "POST", "PUT", "PATCH" -> SwingColors.MEDIUM;
                default -> SwingColors.LOW;
            };
        }

        private static Color severityColor(String s) {
            try {
                return SwingColors.severityFg(Finding.Severity.valueOf(s));
            } catch (IllegalArgumentException e) {
                return SwingColors.MUTED;
            }
        }
    }
}
