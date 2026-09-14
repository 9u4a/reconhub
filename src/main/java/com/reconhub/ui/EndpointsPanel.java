package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.core.DataStore;
import com.reconhub.model.Endpoint;

import java.util.List;

/** Table of deduplicated endpoints with the request/response viewer and shared row menu. */
public final class EndpointsPanel extends AbstractTablePanel<Endpoint> {

    private static final String[] COLS =
            {"Method", "Host", "Path", "Status", "Content-Type", "Params", "Source"};

    private final DataStore store;
    private final MessageViewer viewer;

    public EndpointsPanel(DataStore store, MontoyaApi api) {
        super(api);
        this.store = store;
        this.viewer = new MessageViewer(api);
        installDetail(viewer);
    }

    @Override
    protected void onRowSelected(Endpoint e) {
        if (e == null) {
            viewer.show(null);
            viewer.setInfo(" ");
            return;
        }
        viewer.show(e.getMessages());
        StringBuilder info = new StringBuilder();
        if (!e.getParamNames().isEmpty()) {
            info.append("Params: ").append(String.join(", ", e.getParamNames()));
        }
        if (!e.getOrigins().isEmpty()) {
            if (info.length() > 0) {
                info.append("   |   ");
            }
            info.append("Found in: ").append(String.join(", ", e.getOrigins()));
        }
        if (info.length() == 0) {
            info.append(e.getMethod()).append(' ').append(e.getNormalizedUrl());
        }
        viewer.setInfo(info.toString());
    }

    @Override
    protected String rowUrl(Endpoint e) {
        return e != null && e.getNormalizedUrl().startsWith("http") ? e.getNormalizedUrl() : null;
    }

    @Override
    protected HttpRequestResponse rowMessages(Endpoint e) {
        return e == null ? null : e.getMessages();
    }

    @Override protected boolean supportsBodySearch() { return true; }

    @Override
    protected String searchableBody(Endpoint e) {
        return e == null ? null : MessageViewer.toSearchText(e.getMessages());
    }

    @Override protected List<Endpoint> supplyRows() { return store.snapshotEndpoints(); }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{60, 160, 340, 60, 160, 60, 90};
    }

    @Override protected Object valueAt(Endpoint e, int c) {
        return switch (c) {
            case 0 -> e.getMethod();
            case 1 -> e.getHost();
            case 2 -> e.getPath();
            case 3 -> e.getLastStatusCode() == 0 ? "" : e.getLastStatusCode();
            case 4 -> shortCt(e.getContentType());
            case 5 -> e.getParamCount();
            case 6 -> String.join(",", e.getSources());
            default -> "";
        };
    }

    private static String shortCt(String ct) {
        return ct == null ? "" : ct.split(";")[0].trim();
    }
}
