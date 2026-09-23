package com.reconhub.ui;

import burp.api.montoya.ui.Theme;
import com.reconhub.core.ApiStub;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code SwingColors.isDark()} -- 0.37.0 dark-theme support. Burp's Theme API is poll-only (confirmed
 * via {@code javap} against montoya-api 2023.12.1: {@code UserInterface} has no change-notification
 * callback), so this is the one piece of the theme feature that's pure logic and can be verified
 * headlessly; everything else (actual color legibility) needs a manual Burp smoke test in both themes.
 *
 * <p>Same-package test (SwingColors is package-private by design), and resets {@code SwingColors}'
 * static {@code api} field after each test so this doesn't leak state into other test classes that
 * happen to run in the same JVM/test worker.
 */
class SwingColorsTest {

    @AfterEach
    void resetInit() {
        SwingColors.init(null);
    }

    @Test
    void defaultsToDarkBeforeInit() {
        SwingColors.init(null);
        assertTrue(SwingColors.isDark(), "no api yet -- every color here was originally dark-tuned, so "
                + "dark must stay the safe default");
    }

    @Test
    void reflectsDarkTheme() {
        ApiStub stub = new ApiStub();
        stub.setTheme(Theme.DARK);
        SwingColors.init(stub.api);
        assertTrue(SwingColors.isDark());
    }

    @Test
    void reflectsLightTheme() {
        ApiStub stub = new ApiStub();
        stub.setTheme(Theme.LIGHT);
        SwingColors.init(stub.api);
        assertFalse(SwingColors.isDark());
    }

    @Test
    void picksUpALiveThemeFlip() {
        ApiStub stub = new ApiStub();
        stub.setTheme(Theme.DARK);
        SwingColors.init(stub.api);
        assertTrue(SwingColors.isDark());

        stub.setTheme(Theme.LIGHT);
        assertFalse(SwingColors.isDark(), "isDark() re-polls every call -- no caching to go stale");
    }

    @Test
    void lineAndBannerColorsDifferBetweenThemes() {
        ApiStub stub = new ApiStub();
        SwingColors.init(stub.api);

        stub.setTheme(Theme.DARK);
        var darkLine = SwingColors.line();
        var darkBannerBg = SwingColors.bannerBg();
        var darkBannerFg = SwingColors.bannerFg();

        stub.setTheme(Theme.LIGHT);
        var lightLine = SwingColors.line();
        var lightBannerBg = SwingColors.bannerBg();
        var lightBannerFg = SwingColors.bannerFg();

        // These three were the ones actually confirmed dark-tuned this round (a near-black separator,
        // a near-black-red banner) -- they must have a real, distinct light-theme variant, not just
        // fall through to the same hardcoded value regardless of theme.
        assertFalse(darkLine.equals(lightLine), "line() must differ between themes");
        assertFalse(darkBannerBg.equals(lightBannerBg), "bannerBg() must differ between themes");
        assertFalse(darkBannerFg.equals(lightBannerFg), "bannerFg() must differ between themes");
    }
}
