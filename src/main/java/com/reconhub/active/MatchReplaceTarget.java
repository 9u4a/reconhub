package com.reconhub.active;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * One row selected for a Match & Replace send -- decouples {@link MatchReplaceEngine} from any one
 * model type. All four source row types ({@code model.Endpoint}/{@code ParameterInfo}/{@code Finding}/
 * {@code JsAsset}, 0.43.0) already carry a {@code getMessages()} (added 0.34.0, for the message viewer),
 * which is the one thing actually needed to replay a request -- {@code host}/{@code path}/{@code
 * method} here are for display (the results table, and error messages) only; the request that's
 * actually sent always comes from {@link #messages()}{@code .request()}, and the scope check uses that
 * request's own {@code .url()}, not a separately-carried URL.
 *
 * <p>Each source panel builds these from its own row using whatever it has (see {@code
 * EndpointsPanel.selectedEndpoints()} and the equivalent {@code selectedX()} helpers on {@code
 * ParametersPanel}/{@code FindingsPanel}/{@code JsAssetsPanel}) -- {@code active} package code never
 * needs to know about those model classes.
 */
public record MatchReplaceTarget(String host, String path, String method, HttpRequestResponse messages) {
}
