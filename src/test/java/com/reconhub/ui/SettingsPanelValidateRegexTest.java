package com.reconhub.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code SettingsPanel.validateRegex} -- the UI-level gate that stops an invalid Include/Exclude regex
 * from ever reaching {@code Settings}/{@code ScopeFilter} in the normal Apply-button flow (see {@code
 * core.ScopeFilterTest} for what happens if an invalid one gets in some other way -- fails open, not
 * closed, which is exactly why this gate matters). Pure static logic, headless. */
class SettingsPanelValidateRegexTest {

    @Test
    void blankRegexIsValid() {
        assertNull(SettingsPanel.validateRegex("Include", ""));
    }

    @Test
    void aCompilableRegexIsValid() {
        assertNull(SettingsPanel.validateRegex("Include", "api\\.example"));
    }

    @Test
    void anUnbalancedBracketIsRejected() {
        String err = SettingsPanel.validateRegex("Include", "[unterminated");
        assertNotNull(err);
        assertTrue(err.contains("Include"));
    }

    @Test
    void anUnbalancedParenIsRejected() {
        assertNotNull(SettingsPanel.validateRegex("Exclude", "(unterminated"));
    }

    @Test
    void errorMessageNamesWhichFieldFailed() {
        assertTrue(SettingsPanel.validateRegex("Include", "[bad").contains("Include"));
        assertTrue(SettingsPanel.validateRegex("Exclude", "[bad").contains("Exclude"));
    }
}
