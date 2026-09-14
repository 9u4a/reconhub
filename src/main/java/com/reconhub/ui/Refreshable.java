package com.reconhub.ui;

/** A UI component that can reload itself from the {@code DataStore} snapshot. */
public interface Refreshable {
    void refreshData();
}
