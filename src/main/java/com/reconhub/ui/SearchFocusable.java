package com.reconhub.ui;

/** A tab that can take MainTab's Ctrl+F (0.64.0): focus its search box unless focus is inside a viewer. */
interface SearchFocusable {
    void focusSearch();

    boolean isFocusInsideViewer();
}
