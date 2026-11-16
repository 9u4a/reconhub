package com.reconhub.analysis;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Client Flow extraction (0.59.0) on a {@link JsStructure}: one row per API call site -- direct
 * {@code fetch} / {@code axios} (incl. {@code axios.create} instances) / {@code XMLHttpRequest.open} /
 * jQuery {@code $.ajax|get|post}, plus calls through the app's own HTTP wrapper (a function whose body
 * directly calls one of those with a path built from its parameter; followed one level only). Pure, no
 * Montoya; called from {@link JsStructuralAnalyzer}.
 *
 * <p>Only literal structure is read: a path must contain a literal part with a '/' (or start with http);
 * non-literal parts become {@code {name}} placeholders. Body/query keys come from literal object keys in
 * the same scope. Nothing here sends traffic.
 */
public final class JsClientFlows {

    static final int MAX_FLOWS_PER_BODY = 300;
    private static final Set<String> VERBS = Set.of("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS");
    private static final Set<String> AXIOS_NO_DATA = Set.of("get", "delete", "head", "options");
    private static final Set<String> AXIOS_DATA = Set.of("post", "put", "patch");
    private static final Pattern AUTH_HEADER = Pattern.compile(
            "(?i)^(?:authorization|x-api-key|api-?key|x-auth-token|x-access-token|access-?token|token|x-token|x-jwt)$");
    private static final Pattern HANDLER_KEY = Pattern.compile("^on[A-Z][A-Za-z]{1,30}$");
    private static final Set<String> ROUTE_COMPONENT_KEYS = Set.of("component", "element", "loader", "action",
            "view", "page", "render", "Component", "lazy", "components", "beforeEnter", "resolve");

    /** One extracted call site. */
    public record Hit(String method, String path, List<String> bodyKeys, List<String> queryKeys, String auth,
               String function, String trigger, String via, String callSite) {}

    private final JsStructure st;
    private final Set<String> axiosNames = new HashSet<>(Set.of("axios"));
    private final Map<String, String> instanceAuth = new HashMap<>();   // axios instance -> auth source
    private String globalAuth = "";
    private final Map<String, String> handlerOf = new HashMap<>();      // function name -> "onClick" / "click listener"
    private final Map<String, String> routeOf = new HashMap<>();        // component name -> "/route"
    private final Map<String, Wrapper> wrappers = new LinkedHashMap<>();
    private final List<Hit> out = new ArrayList<>();
    private final Set<String> dedup = new HashSet<>();

    /** A function that wraps a direct call: which parameter is the path, and what its inner call knows. */
    private record Wrapper(String name, int scopeId, int pathParam, String pathTemplate, String paramName,
                           String method, String methodParam, int optionsParam, String auth, String via) {}

    private JsClientFlows(JsStructure st) {
        this.st = st;
    }

    static List<Hit> extract(JsStructure st) {
        JsClientFlows x = new JsClientFlows(st);
        x.collectContext();
        x.directCalls();
        x.wrapperCalls();
        return x.out;
    }

    // ---- context: axios instances, interceptors, handlers, routes -----------------------------

    private void collectContext() {
        for (JsStructure.Assign a : st.assigns) {
            int r = a.rhsStart();
            if (st.isWord(r, "axios") && st.ch(r + 1) == '.' && st.isWord(r + 2, "create")) {
                axiosNames.add(a.name());
            }
        }
        for (int i = 0; i < st.n; i++) {
            // X.interceptors.request.use(fn) / axios.defaults.headers.common.Authorization = ...
            if (st.ident(i) && st.ch(i + 1) == '.' && st.isWord(i + 2, "interceptors") && axiosNames.contains(st.text(i))) {
                int open = findCallOpen(i + 2, 6);
                if (open > 0 && mentionsAuth(open + 1, st.match[open] - 1)) {
                    instanceAuth.put(st.text(i), "Authorization (interceptor)");
                }
            }
            if (st.isWord(i, "defaults") && st.ch(i - 1) == '.' && axiosNames.contains(st.text(i - 2))) {
                int end = Math.min(st.n - 1, i + 12);
                if (mentionsAuth(i, end)) {
                    instanceAuth.put(st.text(i - 2), "Authorization (defaults)");
                    if (st.isWord(i - 2, "axios")) globalAuth = "Authorization (defaults)";
                }
            }
            // onClick: handleSave  /  addEventListener("click", handleSave)
            if (st.ident(i) && st.ch(i + 1) == ':' && HANDLER_KEY.matcher(st.text(i)).matches() && st.ident(i + 2)
                    && !(st.ch(i + 3) == '(' || st.ch(i + 3) == '.')) {
                handlerOf.putIfAbsent(st.text(i + 2), st.text(i));
            }
            if (st.isWord(i, "addEventListener") && st.ch(i + 1) == '(') {
                List<int[]> as = st.args(i + 1);
                if (as.size() >= 2 && st.kind(as.get(0)[0]) == JsLexer.STRING && st.ident(as.get(1)[0])
                        && as.get(1)[0] == as.get(1)[1]) {
                    handlerOf.putIfAbsent(st.text(as.get(1)[0]), st.keyText(as.get(0)[0]) + " listener");
                }
            }
            // route objects: {path: "/x", component: Users}
            if (st.ch(i) == '{' && st.match[i] > i) {
                Map<String, int[]> e = st.objectEntries(i);
                String path = literalOf(e.get("path"));
                if (path != null && path.startsWith("/")) {
                    for (String key : ROUTE_COMPONENT_KEYS) {
                        String comp = componentName(e.get(key));
                        if (comp != null) routeOf.putIfAbsent(comp, path);
                    }
                }
            }
        }
    }

    /** IDENT component reference in a value range: Users, createElement(Users), jsx(Users, ...), lazy(() => ...) skipped. */
    private String componentName(int[] r) {
        if (r == null) return null;
        if (r[0] == r[1] && st.ident(r[0])) return st.text(r[0]);
        for (int k = r[0]; k <= r[1] && k <= r[0] + 8; k++) {
            if (st.ch(k) == '(' && st.ident(k + 1) && Character.isUpperCase(st.text(k + 1).charAt(0))) {
                return st.text(k + 1);
            }
        }
        return null;
    }

    private boolean mentionsAuth(int from, int to) {
        for (int k = Math.max(0, from); k <= to && k < st.n && k <= from + 400; k++) {
            byte kd = st.kind(k);
            if ((kd == JsLexer.IDENT || kd == JsLexer.STRING) && st.keyText(k).toLowerCase(Locale.ROOT).contains("authorization")) {
                return true;
            }
        }
        return false;
    }

    /** '(' of the first call reached by following a member chain from {@code i}, within {@code steps}. */
    private int findCallOpen(int i, int steps) {
        int e = i;
        for (int s = 0; s < steps; s++) {
            if (st.ch(e + 1) == '(' && st.match[e + 1] > e + 1) return e + 1;
            if (st.ch(e + 1) == '.' && st.ident(e + 2)) e += 2; else return -1;
        }
        return -1;
    }

    // ---- direct call sites --------------------------------------------------------------

    private void directCalls() {
        for (int i = 0; i < st.n && out.size() < MAX_FLOWS_PER_BODY; i++) {
            if (!st.ident(i)) continue;
            String w = st.text(i);
            boolean member = st.ch(i - 1) == '.';
            if (w.equals("fetch") && st.ch(i + 1) == '(' && (!member || isGlobalRecv(i - 2))) {
                fetchCall(i, i + 1);
            } else if (axiosNames.contains(w) && !member) {
                axiosCall(i);
            } else if (w.equals("open") && member && st.ch(i + 1) == '(') {
                xhrCall(i);
            } else if ((w.equals("$") || w.equals("jQuery")) && !member && st.ch(i + 1) == '.' && st.ident(i + 2)
                    && st.ch(i + 3) == '(') {
                jqueryCall(i, st.text(i + 2), i + 3);
            }
        }
    }

    private boolean isGlobalRecv(int i) {
        return st.isWord(i, "window") || st.isWord(i, "self") || st.isWord(i, "globalThis");
    }

    private void fetchCall(int at, int open) {
        List<int[]> as = st.args(open);
        if (as.isEmpty()) return;
        String method = "GET";   // null = decided by the caller (a wrapper's options / method parameter)
        List<String> body = List.of();
        String auth = "";
        if (as.size() >= 2) {
            Map<String, int[]> opt = objectAt(as.get(1), st.scope[open]);
            String m = literalOf(opt.get("method"));
            if (m != null) method = m.toUpperCase(Locale.ROOT);
            else if (opt.isEmpty() || opt.containsKey("method")) method = null;
            body = keysOf(opt.get("body"), st.scope[open]);
            auth = authOf(opt.get("headers"), st.scope[open]);
            if (auth.isEmpty() && "include".equals(literalOf(opt.get("credentials")))) auth = "cookies (credentials: include)";
        }
        emit(at, as.get(0), method, body, auth, "fetch", null);
    }

    private void axiosCall(int i) {
        String name = st.text(i);
        int scopeId = st.scope[i];
        String instAuth = instanceAuth.getOrDefault(name, globalAuth);   // axios.create inherits axios.defaults
        if (st.ch(i + 1) == '.' && st.ident(i + 2) && st.ch(i + 3) == '(') {
            String verb = st.text(i + 2);
            List<int[]> as = st.args(i + 3);
            if (as.isEmpty()) return;
            if (AXIOS_NO_DATA.contains(verb) || AXIOS_DATA.contains(verb)) {
                List<String> body = AXIOS_DATA.contains(verb) && as.size() >= 2 ? keysOf(as.get(1), scopeId) : List.of();
                int cfgIdx = AXIOS_DATA.contains(verb) ? 2 : 1;
                Map<String, int[]> cfg = as.size() > cfgIdx ? objectAt(as.get(cfgIdx), scopeId) : Map.of();
                String auth = firstNonEmpty(authOf(cfg.get("headers"), scopeId), instAuth);
                emit(i, as.get(0), verb.toUpperCase(Locale.ROOT), body, auth, axiosVia(name),
                        keysOf(cfg.get("params"), scopeId));
            } else if (verb.equals("request")) {
                axiosConfig(i, as.get(0), scopeId, instAuth, name);
            }
        } else if (st.ch(i + 1) == '(') {
            List<int[]> as = st.args(i + 1);
            if (as.isEmpty()) return;
            if (st.ch(as.get(0)[0]) == '{') {
                axiosConfig(i, as.get(0), scopeId, instAuth, name);
            } else {
                Map<String, int[]> cfg = as.size() >= 2 ? objectAt(as.get(1), scopeId) : Map.of();
                emit(i, as.get(0), methodOf(cfg), keysOf(cfg.get("data"), scopeId),
                        firstNonEmpty(authOf(cfg.get("headers"), scopeId), instAuth), axiosVia(name),
                        keysOf(cfg.get("params"), scopeId));
            }
        }
    }

    private void axiosConfig(int at, int[] cfgRange, int scopeId, String instAuth, String name) {
        Map<String, int[]> cfg = objectAt(cfgRange, scopeId);
        int[] url = cfg.get("url");
        if (url == null) return;
        emit(at, url, methodOf(cfg), keysOf(cfg.get("data"), scopeId),
                firstNonEmpty(authOf(cfg.get("headers"), scopeId), instAuth), axiosVia(name),
                keysOf(cfg.get("params"), scopeId));
    }

    /** Literal method of a config object: GET when absent, null when present but not literal. */
    private String methodOf(Map<String, int[]> cfg) {
        String m = literalOf(cfg.get("method"));
        if (m != null) return m.toUpperCase(Locale.ROOT);
        return cfg.containsKey("method") ? null : "GET";
    }

    private static String axiosVia(String name) {
        return name.equals("axios") ? "axios" : "axios instance " + name;
    }

    private void xhrCall(int i) {
        List<int[]> as = st.args(i + 1);
        if (as.size() < 2) return;
        String verb = literalOf(as.get(0));
        if (verb == null || !VERBS.contains(verb.toUpperCase(Locale.ROOT))) return;
        String recv = st.ident(i - 2) ? st.text(i - 2) : "";
        int scopeId = st.scope[i];
        JsStructure.Scope sc = st.scopes.get(scopeId);
        List<String> body = List.of();
        String auth = "";
        int stop = Math.min(sc.bodyEnd, i + JsStructuralAnalyzer.MAX_SCAN);
        for (int k = i; k <= stop; k++) {
            if (st.scope[k] != scopeId || st.ch(k) != '.' || !st.isWord(k - 1, recv) || st.ch(k + 2) != '(') continue;
            if (st.isWord(k + 1, "send") && body.isEmpty()) {
                List<int[]> sa = st.args(k + 2);
                if (!sa.isEmpty()) body = keysOf(sa.get(0), scopeId);
            } else if (st.isWord(k + 1, "setRequestHeader") && auth.isEmpty()) {
                List<int[]> ha = st.args(k + 2);
                String h = ha.isEmpty() ? null : literalOf(ha.get(0));
                if (h != null && AUTH_HEADER.matcher(h).matches()) {
                    auth = h + (ha.size() > 1 ? storageHint(ha.get(1)) : "");
                }
            } else if (st.isWord(k + 1, "withCredentials") && auth.isEmpty()) {
                auth = "cookies (withCredentials)";
            }
        }
        emit(i, as.get(1), verb.toUpperCase(Locale.ROOT), body, auth, "XMLHttpRequest", null);
    }

    private void jqueryCall(int at, String fn, int open) {
        List<int[]> as = st.args(open);
        if (as.isEmpty()) return;
        int scopeId = st.scope[open];
        switch (fn) {
            case "ajax" -> {
                Map<String, int[]> cfg;
                int[] url;
                if (st.ch(as.get(0)[0]) == '{') {
                    cfg = objectAt(as.get(0), scopeId);
                    url = cfg.get("url");
                } else {
                    url = as.get(0);
                    cfg = as.size() >= 2 ? objectAt(as.get(1), scopeId) : Map.of();
                }
                if (url == null) return;
                String m = firstNonEmpty(nz(literalOf(cfg.get("method"))), nz(literalOf(cfg.get("type"))));
                emit(at, url, m.isEmpty() ? "GET" : m.toUpperCase(Locale.ROOT), keysOf(cfg.get("data"), scopeId),
                        authOf(cfg.get("headers"), scopeId), "jQuery.ajax", null);
            }
            case "get", "post", "getJSON" -> emit(at, as.get(0), fn.equals("post") ? "POST" : "GET",
                    as.size() >= 2 ? keysOf(as.get(1), scopeId) : List.of(), "", "jQuery." + fn, null);
            default -> { }
        }
    }

    // ---- wrappers ---------------------------------------------------------------------------

    /** Records a wrapper when a direct call's path uses a parameter of the function it sits in. */
    private void maybeWrapper(int callSig, int[] pathRange, String method, String auth, String via, String template) {
        int scopeId = st.scope[callSig];
        if (scopeId == 0) return;
        JsStructure.Scope sc = st.scopes.get(scopeId);
        if (sc.name.isEmpty() || sc.params.isEmpty() || wrappers.containsKey(sc.name)) return;
        List<String> params = new ArrayList<>(sc.params);
        int pathParam = -1;
        String paramName = null;
        for (int k = pathRange[0]; k <= pathRange[1]; k++) {
            if (st.isVarRef(k) && params.contains(st.text(k))) {
                pathParam = params.indexOf(st.text(k));
                paramName = st.text(k);
                break;
            }
        }
        if (pathParam < 0) return;
        String methodParam = null;
        int optionsParam = -1;
        if (method == null) {
            // method comes from a parameter (method) or an options parameter (opts.method)
            for (String p : params) {
                if (p.equalsIgnoreCase("method") || p.equalsIgnoreCase("type")) methodParam = p;
            }
            for (int k = 0; k < params.size(); k++) {
                String p = params.get(k).toLowerCase(Locale.ROOT);
                if (k != pathParam && (p.contains("opt") || p.contains("config") || p.equals("init") || p.equals("cfg"))) {
                    optionsParam = k;
                    break;
                }
            }
        }
        wrappers.put(sc.name, new Wrapper(sc.name, scopeId, pathParam, template, paramName, method, methodParam,
                optionsParam, auth, via));
    }

    private void wrapperCalls() {
        if (wrappers.isEmpty()) return;
        for (int i = 0; i < st.n && out.size() < MAX_FLOWS_PER_BODY; i++) {
            if (!st.ident(i) || st.ch(i + 1) != '(') continue;
            Wrapper w = wrappers.get(st.text(i));
            if (w == null) continue;
            JsStructure.Scope ws = st.scopes.get(w.scopeId);
            if (i >= ws.head && i <= ws.bodyEnd) continue;              // recursion / the definition itself
            if (st.isWord(i - 1, "function")) continue;
            List<int[]> as = st.args(i + 1);
            if (as.size() <= w.pathParam) continue;
            int scopeId = st.scope[i];
            String callerPath = template(as.get(w.pathParam), scopeId);
            if (callerPath == null || !hasLiteralPath(callerPath)) continue;   // wrapper-of-wrapper / non-literal
            String path = w.pathTemplate.replace("{" + w.paramName + "}", callerPath);
            String method = w.method;
            List<String> body = new ArrayList<>();
            for (int k = 0; k < as.size(); k++) {
                if (k == w.pathParam) continue;
                String lit = literalOf(as.get(k));
                if (method == null && lit != null && VERBS.contains(lit.toUpperCase(Locale.ROOT))) {
                    method = lit.toUpperCase(Locale.ROOT);
                    continue;
                }
                Map<String, int[]> obj = objectAt(as.get(k), scopeId);
                if (obj.isEmpty()) continue;
                if (obj.containsKey("method") || obj.containsKey("headers") || obj.containsKey("body")
                        || obj.containsKey("data") || k == w.optionsParam) {
                    String m = literalOf(obj.get("method"));
                    if (method == null && m != null) method = m.toUpperCase(Locale.ROOT);
                    body.addAll(keysOf(obj.containsKey("body") ? obj.get("body") : obj.get("data"), scopeId));
                } else {
                    body.addAll(obj.keySet());
                }
            }
            if (method == null) method = verbFromName(w.name);
            add(i, path, method, body, List.of(), w.auth, "wrapper " + w.name + "() → " + w.via,
                    snippetAt(i, as.get(w.pathParam)[1]));
        }
    }

    private static String verbFromName(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        if (n.startsWith("post") || n.endsWith("post")) return "POST";
        if (n.startsWith("put") || n.endsWith("put")) return "PUT";
        if (n.startsWith("patch") || n.endsWith("patch")) return "PATCH";
        if (n.startsWith("del") || n.endsWith("delete") || n.startsWith("remove")) return "DELETE";
        return "GET";
    }

    // ---- emit -----------------------------------------------------------------------------------

    private void emit(int at, int[] pathRange, String method, List<String> body, String auth, String via,
                      List<String> extraQuery) {
        int scopeId = st.scope[at];
        String tpl = template(pathRange, scopeId);
        if (tpl == null) return;
        boolean literal = hasLiteralPath(tpl);
        // a direct call whose path comes from the enclosing function's parameter makes it a wrapper
        maybeWrapper(at, pathRange, method, auth, via, tpl);
        if (!literal) return;
        add(at, tpl, method == null ? "GET" : method, body, extraQuery == null ? List.of() : extraQuery, auth, via, snippetAt(at, pathRange[1]));
    }

    private void add(int at, String tpl, String method, List<String> body, List<String> extraQuery, String auth,
                     String via, String callSite) {
        String path = tpl;
        Set<String> query = new LinkedHashSet<>(extraQuery);
        int q = path.indexOf('?');
        if (q >= 0) {
            for (String part : path.substring(q + 1).split("&")) {
                int eq = part.indexOf('=');
                String k = (eq >= 0 ? part.substring(0, eq) : part).trim();
                if (!k.isEmpty() && !k.startsWith("{")) query.add(k);
            }
            path = path.substring(0, q);
        }
        int h = path.indexOf('#');
        if (h >= 0) path = path.substring(0, h);
        path = collapseSlashes(path);
        if (path.isEmpty()) return;
        String key = method + " " + path;
        if (!dedup.add(key)) return;
        List<JsStructure.Scope> enc = st.enclosing(at);
        String fn = "";
        for (JsStructure.Scope s : enc) {
            if (!s.name.isEmpty()) { fn = s.name; break; }
        }
        out.add(new Hit(method, path, List.copyOf(new LinkedHashSet<>(body)), List.copyOf(query), nz(auth), fn,
                trigger(at, enc), via, callSite));
    }

    /** Route the call sits under (route object it is lexically in, or a routed component enclosing it) and
     * the event handler that runs it, joined; "" when neither is found. */
    private String trigger(int at, List<JsStructure.Scope> enc) {
        String route = null;
        int p = st.parent[at];
        for (int level = 0; p >= 0 && level < 10 && route == null; level++, p = st.parent[p]) {
            if (st.ch(p) == '{') {
                String path = literalOf(st.objectEntries(p).get("path"));
                if (path != null && path.startsWith("/")) route = path;
            }
        }
        String handler = null;
        for (JsStructure.Scope s : enc) {
            if (route == null && !s.name.isEmpty() && routeOf.containsKey(s.name)) route = routeOf.get(s.name);
            if (handler == null) {
                if (!s.name.isEmpty() && handlerOf.containsKey(s.name)) {
                    handler = handlerOf.get(s.name);
                } else if (HANDLER_KEY.matcher(s.name).matches()) {
                    handler = s.name;                                  // onClick: () => fetch(...)
                } else if (st.ch(s.head - 1) == ',' ) {
                    int open = st.parent[s.head];
                    if (open > 0 && st.isWord(open - 1, "addEventListener")) {
                        List<int[]> as = st.args(open);
                        if (!as.isEmpty() && st.kind(as.get(0)[0]) == JsLexer.STRING) {
                            handler = st.keyText(as.get(0)[0]) + " listener";
                        }
                    }
                }
            }
        }
        List<String> parts = new ArrayList<>(2);
        if (route != null) parts.add("route " + route);
        if (handler != null) parts.add(handler);
        return String.join(" · ", parts);
    }

    // ---- expression helpers --------------------------------------------------------------------

    /**
     * Path template for an expression: string / template literals and {@code +} concatenation, other
     * operands as {@code {name}} placeholders (a same-scope or top-level string constant is inlined).
     * Null when the expression isn't a plain concatenation.
     */
    String template(int[] r, int scopeId) {
        return template(r, scopeId, 0);
    }

    private String template(int[] r, int scopeId, int depth) {
        if (r == null || r[0] > r[1] || depth > 2) return null;
        StringBuilder sb = new StringBuilder();
        int i = r[0];
        while (i <= r[1]) {
            byte k = st.kind(i);
            if (k == JsLexer.STRING) {
                sb.append(st.keyText(i));
                i++;
            } else if (k == JsLexer.TEMPLATE) {
                sb.append(templateLiteral(st.text(i)));
                i++;
            } else if (k == JsLexer.IDENT || st.ch(i) == '(') {
                // one operand: member chain / call, up to the next depth-0 '+'
                int end = i;
                String last = null;
                while (end <= r[1] && st.ch(end) != '+') {
                    if ((st.ch(end) == '(' || st.ch(end) == '[') && st.match[end] > end) {
                        end = st.match[end] + 1;
                        continue;
                    }
                    if (st.ch(end) == '?' || st.ch(end) == ':' || st.ch(end) == '|' || st.ch(end) == '&') return null;
                    if (st.ident(end)) last = st.text(end);
                    end++;
                }
                String inlined = (end - 1 == i && st.ident(i)) ? constant(st.text(i), scopeId, depth) : null;
                sb.append(inlined != null ? inlined : "{" + (last == null ? "param" : last) + "}");
                i = end;
            } else if (k == JsLexer.NUMBER) {
                sb.append(st.text(i));
                i++;
            } else {
                return null;
            }
            if (i <= r[1]) {
                if (st.ch(i) != '+') return null;
                i++;
            }
        }
        return sb.toString();
    }

    /** A string constant bound to {@code name}: assigned once in this scope or at top level, RHS a plain template. */
    private String constant(String name, int scopeId, int depth) {
        for (int s : new int[]{scopeId, 0}) {
            List<JsStructure.Assign> as = st.assignsTo(s, name);
            if (as.size() == 1) {
                JsStructure.Assign a = as.get(0);
                byte k = st.kind(a.rhsStart());
                if (k == JsLexer.STRING || k == JsLexer.TEMPLATE) {
                    return template(new int[]{a.rhsStart(), a.rhsEnd()}, s, depth + 1);
                }
            }
            if (s == 0) break;
        }
        return null;
    }

    /** `/api/${user.id}/x` → /api/{id}/x (last identifier of each expression). */
    static String templateLiteral(String raw) {
        String body = raw.length() >= 2 ? raw.substring(1, raw.length() - (raw.endsWith("`") ? 1 : 0)) : "";
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < body.length()) {
            char c = body.charAt(i);
            if (c == '\\' && i + 1 < body.length()) {
                sb.append(body.charAt(i + 1));
                i += 2;
            } else if (c == '$' && i + 1 < body.length() && body.charAt(i + 1) == '{') {
                int depth = 1;
                int j = i + 2;
                while (j < body.length() && depth > 0) {
                    char d = body.charAt(j);
                    if (d == '{') depth++;
                    else if (d == '}') depth--;
                    j++;
                }
                String expr = body.substring(i + 2, Math.max(i + 2, j - 1));
                sb.append('{').append(placeholderName(expr)).append('}');
                i = j;
            } else {
                sb.append(c);
                i++;
            }
        }
        return sb.toString();
    }

    private static final Pattern IDENT_RE = Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*");

    private static String placeholderName(String expr) {
        java.util.regex.Matcher m = IDENT_RE.matcher(expr);
        String last = null;
        while (m.find()) {
            int after = m.end();
            while (after < expr.length() && expr.charAt(after) == ' ') after++;
            boolean call = after < expr.length() && expr.charAt(after) == '(';
            if (!call && !JsStructure.KEYWORDS.contains(m.group())) last = m.group();
        }
        return last == null ? "param" : last;
    }

    /** Literal string value of a single-token value range, else null. */
    private String literalOf(int[] r) {
        if (r == null || r[0] != r[1]) return null;
        byte k = st.kind(r[0]);
        if (k == JsLexer.STRING) return st.keyText(r[0]);
        if (k == JsLexer.TEMPLATE && !st.text(r[0]).contains("${")) return templateLiteral(st.text(r[0]));
        return null;
    }

    /** Object-literal entries of a range: the literal itself, or a same-scope variable assigned one. */
    private Map<String, int[]> objectAt(int[] r, int scopeId) {
        if (r == null) return Map.of();
        if (st.ch(r[0]) == '{') return st.objectEntries(r[0]);
        if (r[0] == r[1] && st.isVarRef(r[0])) {
            List<JsStructure.Assign> as = st.assignsTo(scopeId, st.text(r[0]));
            if (as.size() == 1 && st.ch(as.get(0).rhsStart()) == '{') return st.objectEntries(as.get(0).rhsStart());
        }
        return Map.of();
    }

    /** Literal keys of a body/params value: {a,b}, JSON.stringify({..}), new URLSearchParams({..}), a variable. */
    private List<String> keysOf(int[] r, int scopeId) {
        if (r == null) return List.of();
        Map<String, int[]> obj = objectAt(r, scopeId);
        if (!obj.isEmpty()) return new ArrayList<>(obj.keySet());
        // wrapper call: X.stringify(arg) / new URLSearchParams(arg) / qs.stringify(arg)
        for (int k = r[0]; k <= r[1] && k <= r[0] + 6; k++) {
            if (st.ch(k) == '(' && st.match[k] > k) {
                List<int[]> as = st.args(k);
                if (!as.isEmpty()) {
                    Map<String, int[]> inner = objectAt(as.get(0), scopeId);
                    if (!inner.isEmpty()) return new ArrayList<>(inner.keySet());
                }
                break;
            }
        }
        return List.of();
    }

    /** Auth header named in a headers object (with its storage source when visible), else "". */
    private String authOf(int[] r, int scopeId) {
        Map<String, int[]> h = objectAt(r, scopeId);
        for (Map.Entry<String, int[]> e : h.entrySet()) {
            if (AUTH_HEADER.matcher(e.getKey()).matches()) {
                return e.getKey() + storageHint(e.getValue());
            }
        }
        return "";
    }

    private String storageHint(int[] r) {
        for (int k = r[0]; k <= r[1] && k <= r[0] + 40; k++) {
            String t = st.text(k);
            if (t.equals("localStorage")) return " (localStorage)";
            if (t.equals("sessionStorage")) return " (sessionStorage)";
            if (t.equals("cookie")) return " (cookie)";
        }
        return "";
    }

    private String snippetAt(int fromSig, int toSig) {
        int s = st.startOffset(fromSig);
        int e = st.endOffset(Math.min(toSig, st.n - 1));
        String t = st.src.substring(s, Math.min(e, s + 160)).replaceAll("\\s+", " ");
        return t;
    }

    static boolean hasLiteralPath(String tpl) {
        String lit = tpl.replaceAll("\\{[^}]{0,60}}", "");
        return tpl.startsWith("/") || tpl.startsWith("http://") || tpl.startsWith("https://")
                || (lit.contains("/") && !lit.isBlank());
    }

    private static String collapseSlashes(String p) {
        int scheme = p.indexOf("://");
        String head = scheme >= 0 ? p.substring(0, scheme + 3) : "";
        String rest = scheme >= 0 ? p.substring(scheme + 3) : p;
        return head + rest.replaceAll("/{2,}", "/");
    }

    private static String firstNonEmpty(String a, String b) {
        return a != null && !a.isEmpty() ? a : (b == null ? "" : b);
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
