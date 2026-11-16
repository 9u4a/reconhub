package com.reconhub.active;

import java.util.List;

/**
 * One identity a Match &amp; Replace run sends as (0.61.0): its name (a session, "Original", "No auth", or
 * "Custom") and the full rule chain applied for it -- the session's rules plus any common extra rules.
 */
public record RunIdentity(String name, List<MatchReplaceRule> rules) {
    public RunIdentity {
        name = name == null ? "" : name;
        rules = List.copyOf(rules == null ? List.of() : rules);
    }
}
