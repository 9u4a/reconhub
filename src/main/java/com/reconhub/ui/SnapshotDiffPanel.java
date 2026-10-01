package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import com.reconhub.core.DataStore;
import com.reconhub.core.KeyedDiff;
import com.reconhub.export.StateSerializer;
import com.reconhub.model.Endpoint;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;
import com.reconhub.model.ParameterInfo;
import com.reconhub.model.TechInfo;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingWorker;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.io.File;
import java.util.List;
import java.util.function.Function;

/**
 * Compares a loaded State export file against the live {@link DataStore} and shows what's new/gone
 * since that snapshot -- deferred twice (0.36.0, 0.37.0 Tier C "snapshot diff") before 0.43.0.
 *
 * <p>Unlike every other tab, this one is <b>not</b> continuously live -- {@link #refreshData()} is a
 * no-op; the diff is computed once per "Load comparison state file…" click, against whatever the live
 * store looks like at that moment. Reuses {@code export.StateSerializer}'s existing 3-arg {@code
 * importInto(DataStore, Path, boolean)} to parse the file into a throwaway {@link DataStore} (never
 * touching the live one), then {@link KeyedDiff#compute} per collection, keyed by each model's own
 * {@code key()}.
 *
 * <p>v1 scope is Added/Removed only -- "Changed" (same key, different content) needs a different,
 * per-type comparison and is deferred; there's also no request/response detail viewer here (the
 * comparison file's rows only have one if it was exported with "include messages" on, which would make
 * the viewer inconsistently available row to row) -- just the summary tables below.
 */
public final class SnapshotDiffPanel extends JPanel implements Refreshable {

    private final MontoyaApi api;
    private final DataStore liveStore;
    private final JLabel summary = new JLabel("Load a saved State export file to compare against the current data.");

    private final DiffTableModel<Endpoint> endpointsModel = new DiffTableModel<>(
            new String[]{"Change", "Method", "Host", "Path"},
            e -> new Object[]{e.getMethod(), e.getHost(), e.getPath()});
    private final DiffTableModel<ParameterInfo> parametersModel = new DiffTableModel<>(
            new String[]{"Change", "Host", "Endpoint", "Name"},
            p -> new Object[]{p.getHost(), p.getEndpointPath(), p.getName()});
    private final DiffTableModel<Finding> findingsModel = new DiffTableModel<>(
            new String[]{"Change", "Severity", "Type", "Location"},
            f -> new Object[]{f.getSeverity().name(), f.getType(), f.getLocationUrl()});
    private final DiffTableModel<JsAsset> jsAssetsModel = new DiffTableModel<>(
            new String[]{"Change", "URL"},
            a -> new Object[]{a.getUrl()});
    private final DiffTableModel<TechInfo> techModel = new DiffTableModel<>(
            new String[]{"Change", "Host", "Technologies"},
            t -> new Object[]{t.getHost(), String.join(", ", t.getTechnologies())});

    public SnapshotDiffPanel(MontoyaApi api, DataStore liveStore) {
        this.api = api;
        this.liveStore = liveStore;
        setLayout(new BorderLayout(0, 10));
        setBorder(BorderFactory.createEmptyBorder(12, 14, 12, 14));

        JButton load = new JButton("Load comparison state file…");
        load.setToolTipText("Pick a previously-exported State JSON file (Settings → Backup / State) "
                + "to compare against the current data");
        load.addActionListener(e -> loadAndDiff());
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        top.add(load);
        top.add(summary);
        add(top, BorderLayout.NORTH);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Endpoints", tableIn(endpointsModel));
        tabs.addTab("Parameters", tableIn(parametersModel));
        tabs.addTab("Findings", tableIn(findingsModel));
        tabs.addTab("JS Assets", tableIn(jsAssetsModel));
        tabs.addTab("Tech", tableIn(techModel));
        add(tabs, BorderLayout.CENTER);
    }

    /** No-op -- see class javadoc: this tab only updates when the user loads a new comparison file,
     * never on the usual 300ms DataStore-change tick. */
    @Override public void refreshData() {}

    private static JScrollPane tableIn(DiffTableModel<?> model) {
        JTable t = new JTable(model);
        t.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        t.setRowHeight(22);
        t.setDefaultRenderer(Object.class, SwingColors.stripedRenderer());
        return new JScrollPane(t);
    }

    private void loadAndDiff() {
        JFileChooser fc = new JFileChooser(System.getProperty("user.home"));
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = fc.getSelectedFile();
        summary.setText("Loading " + file.getName() + "…");

        new SwingWorker<String, Void>() {
            private Exception error;
            private KeyedDiff.Diff<Endpoint> eDiff;
            private KeyedDiff.Diff<ParameterInfo> pDiff;
            private KeyedDiff.Diff<Finding> fDiff;
            private KeyedDiff.Diff<JsAsset> jDiff;
            private KeyedDiff.Diff<TechInfo> tDiff;

            @Override protected String doInBackground() {
                try {
                    DataStore compareStore = new DataStore();
                    StateSerializer.importInto(compareStore, file.toPath(), true);
                    eDiff = KeyedDiff.compute(compareStore.snapshotEndpoints(),
                            liveStore.snapshotEndpoints(), Endpoint::key);
                    pDiff = KeyedDiff.compute(compareStore.snapshotParameters(),
                            liveStore.snapshotParameters(), ParameterInfo::key);
                    fDiff = KeyedDiff.compute(compareStore.snapshotFindings(),
                            liveStore.snapshotFindings(), Finding::key);
                    jDiff = KeyedDiff.compute(compareStore.snapshotJsAssets(),
                            liveStore.snapshotJsAssets(), JsAsset::key);
                    tDiff = KeyedDiff.compute(compareStore.snapshotTech(),
                            liveStore.snapshotTech(), TechInfo::key);
                    return "vs " + file.getName() + ":  "
                            + "endpoints +" + eDiff.added().size() + "/-" + eDiff.removed().size() + "   "
                            + "parameters +" + pDiff.added().size() + "/-" + pDiff.removed().size() + "   "
                            + "findings +" + fDiff.added().size() + "/-" + fDiff.removed().size() + "   "
                            + "JS +" + jDiff.added().size() + "/-" + jDiff.removed().size() + "   "
                            + "tech +" + tDiff.added().size() + "/-" + tDiff.removed().size();
                } catch (Exception e) {
                    error = e;
                    return null;
                }
            }

            @Override protected void done() {
                if (error != null) {
                    summary.setText("Load failed: " + error.getMessage());
                    api.logging().logToError("ReconHub snapshot diff: load failed for " + file + ": " + error);
                    return;
                }
                String text;
                try {
                    text = get();
                } catch (Exception e) {
                    text = "Load failed.";
                }
                summary.setText(text);
                endpointsModel.setDiff(eDiff);
                parametersModel.setDiff(pDiff);
                findingsModel.setDiff(fDiff);
                jsAssetsModel.setDiff(jDiff);
                techModel.setDiff(tDiff);
            }
        }.execute();
    }

    /** Flattens a {@link KeyedDiff.Diff} into one table: every added row first (marked "+"), then every
     * removed row ("-") -- {@code columns} is the type-specific display columns, {@code extract} pulls
     * them out of one row (the leading "Change" column is handled here, not by {@code extract}). */
    private static final class DiffTableModel<T> extends AbstractTableModel {
        private final String[] columns;
        private final Function<T, Object[]> extract;
        private List<Object[]> rows = List.of();

        DiffTableModel(String[] columns, Function<T, Object[]> extract) {
            this.columns = columns;
            this.extract = extract;
        }

        void setDiff(KeyedDiff.Diff<T> diff) {
            List<Object[]> next = new java.util.ArrayList<>();
            for (T row : diff.added()) {
                next.add(prepend("+", extract.apply(row)));
            }
            for (T row : diff.removed()) {
                next.add(prepend("−", extract.apply(row)));
            }
            this.rows = next;
            fireTableDataChanged();
        }

        private static Object[] prepend(String change, Object[] rest) {
            Object[] out = new Object[rest.length + 1];
            out[0] = change;
            System.arraycopy(rest, 0, out, 1, rest.length);
            return out;
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int c) { return columns[c]; }
        @Override public Object getValueAt(int row, int col) { return rows.get(row)[col]; }
    }
}
