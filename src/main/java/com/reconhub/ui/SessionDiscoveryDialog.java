package com.reconhub.ui;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.reconhub.active.SessionDiscovery;
import com.reconhub.active.SessionProfiles;
import com.reconhub.core.DataStore;
import com.reconhub.model.Endpoint;
import com.reconhub.model.ParameterInfo;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Window;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

/**
 * "Find in captured traffic" (0.60.0): lists account candidates -- one per host and distinct credential
 * set seen in ReconHub's captured requests -- so the user only ticks and names them. Reads captured data
 * on a background worker; sends nothing.
 */
final class SessionDiscoveryDialog {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("MM-dd HH:mm").withZone(ZoneId.systemDefault());

    private SessionDiscoveryDialog() {}

    static void open(Component owner, DataStore store, SessionProfiles sessions) {
        Window w = owner instanceof Window win ? win : owner == null ? null : SwingUtilities.getWindowAncestor(owner);
        JDialog d = new JDialog(w, "ReconHub — find sessions in captured traffic", java.awt.Dialog.ModalityType.APPLICATION_MODAL);
        JLabel status = new JLabel("Scanning captured requests…");
        status.setBorder(BorderFactory.createEmptyBorder(8, 10, 4, 10));
        Model model = new Model(sessions);
        JTable table = new JTable(model);
        table.setRowHeight(22);
        int[] widths = {40, 120, 160, 220, 170, 110, 60, 90, 90};
        for (int i = 0; i < widths.length; i++) table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        table.setAutoCreateRowSorter(true);

        JButton save = new JButton("Save selected");
        save.setEnabled(false);
        JButton close = new JButton("Close");
        save.addActionListener(e -> {
            if (table.isEditing()) table.getCellEditor().stopCellEditing();
            int saved = 0;
            for (Model.Row r : model.rows) {
                if (!r.pick) continue;
                String name = r.name == null || r.name.isBlank() ? sessions.uniqueName("user") : r.name.trim();
                if (SessionProfiles.isBuiltIn(name)) name = sessions.uniqueName(name + " (captured)");
                sessions.put(new SessionProfiles.Identity(name, r.c.headers(), r.c.cookies(),
                        "captured " + r.c.host(), System.currentTimeMillis()));
                saved++;
            }
            if (saved == 0) {
                JOptionPane.showMessageDialog(d, "Tick the candidates to save.", "ReconHub", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            d.dispose();
        });
        close.addActionListener(e -> d.dispose());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(new JLabel("Name each account (e.g. user A, user B, admin). Kept in memory only.  "));
        buttons.add(close);
        buttons.add(save);
        d.getContentPane().setLayout(new BorderLayout());
        d.getContentPane().add(status, BorderLayout.NORTH);
        JScrollPane sp = new JScrollPane(table);
        sp.setPreferredSize(new Dimension(1060, 320));
        d.getContentPane().add(sp, BorderLayout.CENTER);
        d.getContentPane().add(buttons, BorderLayout.SOUTH);
        d.pack();
        d.setLocationRelativeTo(w);

        new SwingWorker<List<SessionDiscovery.Candidate>, Void>() {
            @Override protected List<SessionDiscovery.Candidate> doInBackground() {
                return SessionDiscovery.discover(samples(store), sessions.list());
            }

            @Override protected void done() {
                try {
                    List<SessionDiscovery.Candidate> found = get();
                    model.load(found);
                    status.setText(found.isEmpty()
                            ? "No auth headers or session cookies found in captured requests. Browse the app "
                            + "logged in as each account first (or paste values via + New session)."
                            : found.size() + " account candidate(s) -- grouped by host and credential values "
                            + "(CSRF tokens ignored). Already-saved ones are marked.");
                    save.setEnabled(!found.isEmpty());
                } catch (Exception ex) {
                    status.setText("Scan failed: " + ex.getMessage());
                }
            }
        }.execute();
        d.setVisible(true);
    }

    /** Captured requests as discovery samples: one per endpoint and parameter row with a stored exchange. */
    private static List<SessionDiscovery.Sample> samples(DataStore store) {
        List<SessionDiscovery.Sample> out = new ArrayList<>();
        Map<HttpRequestResponse, Boolean> seen = new IdentityHashMap<>();
        for (Endpoint e : store.snapshotEndpoints()) {
            add(out, seen, e.getHost(), e.getPath(), e.getMessages(), e.getFirstSeenEpochMs());
            if (out.size() >= SessionDiscovery.MAX_SAMPLES * 2) return out;
        }
        for (ParameterInfo p : store.snapshotParameters()) {
            add(out, seen, p.getHost(), p.getEndpointPath(), p.getMessages(), 0);
            if (out.size() >= SessionDiscovery.MAX_SAMPLES * 2) return out;
        }
        return out;
    }

    private static void add(List<SessionDiscovery.Sample> out, Map<HttpRequestResponse, Boolean> seen, String host,
                            String path, HttpRequestResponse rr, long time) {
        if (rr == null || seen.put(rr, Boolean.TRUE) != null) return;
        try {
            HttpRequest req = rr.request();
            if (req == null) return;
            List<String[]> headers = new ArrayList<>();
            for (HttpHeader h : req.headers()) headers.add(new String[]{h.name(), h.value()});
            out.add(new SessionDiscovery.Sample(host, path, headers, time));
        } catch (RuntimeException ignored) {
            // an unreadable stored exchange is skipped
        }
    }

    private static final class Model extends AbstractTableModel {
        private static final String[] COLS = {"Save", "Name", "Host", "Credentials", "Who (token)", "Expires",
                "Requests", "Last seen", "Saved as"};

        static final class Row {
            final SessionDiscovery.Candidate c;
            boolean pick;
            String name;

            Row(SessionDiscovery.Candidate c, boolean pick, String name) {
                this.c = c;
                this.pick = pick;
                this.name = name;
            }
        }

        final List<Row> rows = new ArrayList<>();
        private final SessionProfiles sessions;

        Model(SessionProfiles sessions) {
            this.sessions = sessions;
        }

        void load(List<SessionDiscovery.Candidate> cs) {
            rows.clear();
            List<String> taken = new ArrayList<>();
            for (SessionDiscovery.Candidate c : cs) {
                String base = SessionEditorDialog.defaultName(c.token());
                String name = sessions.uniqueName(base);
                while (taken.contains(name)) name = name + "'";
                taken.add(name);
                rows.add(new Row(c, false, c.registeredAs().isEmpty() ? name : c.registeredAs()));
            }
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) { return c == 0 ? Boolean.class : c == 6 ? Integer.class : String.class; }
        @Override public boolean isCellEditable(int r, int c) { return c == 0 || c == 1; }

        @Override public Object getValueAt(int r, int col) {
            Row row = rows.get(r);
            SessionDiscovery.Candidate c = row.c;
            return switch (col) {
                case 0 -> row.pick;
                case 1 -> row.name;
                case 2 -> c.host();
                case 3 -> c.summary();
                case 4 -> c.token() == null ? "" : c.token().subject();
                case 5 -> SessionEditorDialog.expiry(c.token());
                case 6 -> c.requests();
                case 7 -> c.lastSeen() <= 0 ? "" : TS.format(Instant.ofEpochMilli(c.lastSeen()));
                default -> c.registeredAs();
            };
        }

        @Override public void setValueAt(Object v, int r, int c) {
            Row row = rows.get(r);
            if (c == 0) row.pick = Boolean.TRUE.equals(v);
            else if (c == 1) row.name = String.valueOf(v);
            fireTableRowsUpdated(r, r);
        }
    }
}
