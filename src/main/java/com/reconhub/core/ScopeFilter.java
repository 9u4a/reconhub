package com.reconhub.core;

import burp.api.montoya.MontoyaApi;

/** Decides whether a URL should be processed, based on the current {@link Settings.ScopeMode}. */
public final class ScopeFilter {

    private final MontoyaApi api;
    private final Settings settings;

    public ScopeFilter(MontoyaApi api, Settings settings) {
        this.api = api;
        this.settings = settings;
    }

    public boolean inScope(String url) {
        if (settings.getScopeMode() == Settings.ScopeMode.ALL) {
            return true;
        }
        try {
            return api.scope().isInScope(url);
        } catch (RuntimeException e) {
            return false;
        }
    }
}
