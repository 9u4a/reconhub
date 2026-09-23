package com.reconhub.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.ui.Theme;
import burp.api.montoya.ui.UserInterface;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

/**
 * Minimal {@link java.lang.reflect.Proxy}-based {@link MontoyaApi} stub for headless tests: records
 * {@code logToError(...)} calls, lets {@code scope().isInScope(...)} be made to throw on demand, backs
 * {@code persistence().preferences()} with an in-memory string map (enough for a
 * Settings/UserRuleStore/Bookmarks-style save/load round-trip), and lets
 * {@code userInterface().currentTheme()} be set on demand (for {@code SwingColors.isDark()}). No real
 * Montoya object-factory call is ever reachable through this stub -- those require the live Burp
 * runtime (confirmed via {@code ObjectFactoryLocator.FACTORY == null} outside Burp) and are out of
 * scope for this helper.
 */
public final class ApiStub {
    public final List<String> errorLog = new ArrayList<>();
    public final MontoyaApi api;
    public final Map<String, String> prefStrings = new ConcurrentHashMap<>();
    private volatile Predicate<String> scopeThrows = url -> false;
    private volatile Theme theme = Theme.DARK;

    public ApiStub() {
        Logging logging = (Logging) Proxy.newProxyInstance(
                Logging.class.getClassLoader(), new Class<?>[]{Logging.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("logToError") && args != null && args.length == 1) {
                        errorLog.add(String.valueOf(args[0]));
                        return null;
                    }
                    return defaultReturn(method);
                });
        Scope scope = (Scope) Proxy.newProxyInstance(
                Scope.class.getClassLoader(), new Class<?>[]{Scope.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("isInScope") && args != null && args.length == 1) {
                        String url = (String) args[0];
                        if (scopeThrows.test(url)) {
                            throw new RuntimeException("stubbed scope failure for " + url);
                        }
                        return true;
                    }
                    return defaultReturn(method);
                });
        Preferences preferences = (Preferences) Proxy.newProxyInstance(
                Preferences.class.getClassLoader(), new Class<?>[]{Preferences.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getString":
                            return prefStrings.get((String) args[0]);
                        case "setString":
                            prefStrings.put((String) args[0], (String) args[1]);
                            return null;
                        case "deleteString":
                            prefStrings.remove((String) args[0]);
                            return null;
                        case "stringKeys":
                            return new HashSet<>(prefStrings.keySet());
                        default:
                            return defaultReturn(method);
                    }
                });
        Persistence persistence = (Persistence) Proxy.newProxyInstance(
                Persistence.class.getClassLoader(), new Class<?>[]{Persistence.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("preferences")) {
                        return preferences;
                    }
                    return defaultReturn(method);
                });
        UserInterface userInterface = (UserInterface) Proxy.newProxyInstance(
                UserInterface.class.getClassLoader(), new Class<?>[]{UserInterface.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("currentTheme")) {
                        return theme;
                    }
                    return defaultReturn(method);
                });
        InvocationHandler apiHandler = (proxy, method, args) -> {
            return switch (method.getName()) {
                case "logging" -> logging;
                case "scope" -> scope;
                case "persistence" -> persistence;
                case "userInterface" -> userInterface;
                default -> defaultReturn(method);
            };
        };
        this.api = (MontoyaApi) Proxy.newProxyInstance(
                MontoyaApi.class.getClassLoader(), new Class<?>[]{MontoyaApi.class}, apiHandler);
    }

    /** Makes scope().isInScope(url) throw a RuntimeException for every subsequent call. */
    public void makeScopeCheckThrow() {
        this.scopeThrows = url -> true;
    }

    /** Sets what userInterface().currentTheme() returns for subsequent calls. */
    public void setTheme(Theme t) {
        this.theme = t;
    }

    private static Object defaultReturn(Method m) {
        Class<?> rt = m.getReturnType();
        if (rt == boolean.class) return false;
        if (rt == int.class) return 0;
        if (rt == long.class) return 0L;
        return null;
    }
}
