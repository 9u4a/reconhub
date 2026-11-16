package com.reconhub.analysis;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@link JsClientFlows} (0.59.0): call-site extraction, path templates, keys, wrappers, triggers. */
class JsClientFlowsTest {

    private static List<JsClientFlows.Hit> flows(String js) {
        return JsClientFlows.extract(JsStructure.of(js));
    }

    private static JsClientFlows.Hit one(String js) {
        List<JsClientFlows.Hit> f = flows(js);
        assertEquals(1, f.size(), f.toString());
        return f.get(0);
    }

    private static JsClientFlows.Hit find(List<JsClientFlows.Hit> f, String method, String path) {
        return f.stream().filter(h -> h.method().equals(method) && h.path().equals(path)).findFirst()
                .orElseThrow(() -> new AssertionError(method + " " + path + " not in " + f));
    }

    // ---- fetch -------------------------------------------------------------------

    @Test
    void fetchWithOptionsObject() {
        JsClientFlows.Hit h = one("function save(u){ return fetch('/api/users/' + u.id, {method: 'PUT',"
                + " headers: {'Content-Type': 'application/json', Authorization: 'Bearer ' + localStorage.getItem('t')},"
                + " body: JSON.stringify({name: n, role: r})}); }");
        assertEquals("PUT", h.method());
        assertEquals("/api/users/{id}", h.path());
        assertEquals(List.of("name", "role"), h.bodyKeys());
        assertEquals("Authorization (localStorage)", h.auth());
        assertEquals("save", h.function());
        assertEquals("fetch", h.via());
    }

    @Test
    void fetchTemplateLiteralWithQuery() {
        JsClientFlows.Hit h = one("const load = async (orderId) => { const r = await fetch(`/api/orders/${orderId}/items?page=${p}&size=20`); };");
        assertEquals("GET", h.method());
        assertEquals("/api/orders/{orderId}/items", h.path());
        assertEquals(List.of("page", "size"), h.queryKeys());
        assertEquals("load", h.function());
    }

    @Test
    void stringConstantBaseIsInlined() {
        JsClientFlows.Hit h = one("const API = '/api/v1'; function list(){ return fetch(API + '/notices'); }");
        assertEquals("/api/v1/notices", h.path());
    }

    @Test
    void nonPathFetchIsIgnored() {
        assertTrue(flows("fetch(url); fetch(a ? b : c); fetch(cfg.endpoint);").isEmpty());
    }

    // ---- axios ----------------------------------------------------------------------

    @Test
    void axiosMethodHelpersAndConfigObject() {
        List<JsClientFlows.Hit> f = flows("axios.get('/api/me');"
                + " axios.post('/api/posts', {title: t, body: b}, {headers: {'X-Api-Key': k}});"
                + " axios({url: '/api/admin/users', method: 'delete', params: {id: i}});"
                + " axios.request({url: `/api/files/${fid}`, method: 'patch', data: {name: n}});");
        assertEquals(4, f.size(), f.toString());
        find(f, "GET", "/api/me");
        JsClientFlows.Hit post = find(f, "POST", "/api/posts");
        assertEquals(List.of("title", "body"), post.bodyKeys());
        assertEquals("X-Api-Key", post.auth());
        assertEquals(List.of("id"), find(f, "DELETE", "/api/admin/users").queryKeys());
        assertEquals(List.of("name"), find(f, "PATCH", "/api/files/{fid}").bodyKeys());
    }

    @Test
    void axiosInstanceWithAuthInterceptor() {
        List<JsClientFlows.Hit> f = flows("const api = axios.create({baseURL: '/'});"
                + " api.interceptors.request.use(c => { c.headers.Authorization = 'Bearer ' + tok; return c; });"
                + " function load(){ return api.get('/api/accounts'); }");
        JsClientFlows.Hit h = find(f, "GET", "/api/accounts");
        assertEquals("Authorization (interceptor)", h.auth());
        assertEquals("axios instance api", h.via());
    }

    // ---- XHR / jQuery ------------------------------------------------------------------

    @Test
    void xhrOpenSendAndHeader() {
        JsClientFlows.Hit h = one("function up(){ var x = new XMLHttpRequest(); x.open('POST', '/api/upload');"
                + " x.setRequestHeader('Authorization', sessionStorage.token); x.send(JSON.stringify({file: f, dir: d})); }");
        assertEquals("POST", h.method());
        assertEquals("/api/upload", h.path());
        assertEquals(List.of("file", "dir"), h.bodyKeys());
        assertEquals("Authorization (sessionStorage)", h.auth());
        assertEquals("XMLHttpRequest", h.via());
    }

    @Test
    void jqueryAjax() {
        JsClientFlows.Hit h = one("$.ajax({url: '/member/modify.do', type: 'POST', data: {memberNo: no, email: e}});");
        assertEquals("POST", h.method());
        assertEquals("/member/modify.do", h.path());
        assertEquals(List.of("memberNo", "email"), h.bodyKeys());
    }

    // ---- dedup -------------------------------------------------------------------------

    @Test
    void sameMethodAndTemplateCollapse() {
        assertEquals(1, flows("fetch('/api/x'); fetch('/api/x'); fetch(\"/api/x\");").size());
        assertEquals(2, flows("fetch('/api/x'); fetch('/api/x', {method: 'POST'});").size());
    }

    // ---- wrappers (#9) -------------------------------------------------------------------

    @Test
    void callsThroughAWrapperUseTheCallersPathAndMethod() {
        List<JsClientFlows.Hit> f = flows("const BASE = '/api';"
                + " function request(path, opts) { return fetch(BASE + path, opts); }"
                + " function del(id){ return request('/users/' + id, {method: 'DELETE'}); }"
                + " function create(){ return request('/users', {method: 'POST', body: JSON.stringify({email: e})}); }");
        assertTrue(f.stream().noneMatch(h -> h.path().contains("{path}")),
                "the wrapper's own inner call is not a flow: " + f);
        JsClientFlows.Hit d = find(f, "DELETE", "/api/users/{id}");
        assertTrue(d.via().startsWith("wrapper request()"), d.via());
        assertEquals("del", d.function());
        assertEquals(List.of("email"), find(f, "POST", "/api/users").bodyKeys());
    }

    @Test
    void methodNamedWrapperAndDataArgument() {
        List<JsClientFlows.Hit> f = flows("const http = { post(url, data) { return axios.post(url, data); } };"
                + " function signup(){ return http.post('/api/signup', {name: n, password: p}); }");
        JsClientFlows.Hit h = find(f, "POST", "/api/signup");
        assertEquals(List.of("name", "password"), h.bodyKeys());
    }

    @Test
    void wrapperOfWrapperIsNotFollowed() {
        List<JsClientFlows.Hit> f = flows("function request(p){ return fetch(p); }"
                + " function apiGet(p){ return request(p); }"
                + " apiGet('/api/never');");
        assertTrue(f.isEmpty(), "one level only, and no wrong rows: " + f);
    }

    // ---- triggers (#9) --------------------------------------------------------------------

    @Test
    void eventHandlerAndRouteTriggers() {
        List<JsClientFlows.Hit> f = flows(
                "function Users(){ function handleDelete(){ fetch('/api/users/1', {method: 'DELETE'}); }"
                        + " return h('button', {onClick: handleDelete}); }"
                        + " const routes = [{path: '/admin/users', component: Users}];"
                        + " btn.addEventListener('submit', function(){ fetch('/api/feedback', {method: 'POST'}); });"
                        + " const r2 = [{path: '/orders', loader: () => fetch('/api/orders')}];");
        assertEquals("route /admin/users · onClick", find(f, "DELETE", "/api/users/1").trigger());
        assertEquals("submit listener", find(f, "POST", "/api/feedback").trigger());
        assertEquals("route /orders", find(f, "GET", "/api/orders").trigger());
    }

    @Test
    void templateLiteralPlaceholderNames() {
        assertEquals("/a/{id}/b/{slug}", JsClientFlows.templateLiteral("`/a/${user.id}/b/${encodeURIComponent(slug)}`"));
        assertEquals("/x/{param}", JsClientFlows.templateLiteral("`/x/${1+2}`"));
    }
}
