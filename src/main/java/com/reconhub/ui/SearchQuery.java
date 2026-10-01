package com.reconhub.ui;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Parses a ReconHub search-box query into compiled include/exclude patterns and tests a haystack
 * string against them. Extracted from {@code AbstractTablePanel.applySearch}/{@code SearchFilter}
 * (0.43.0) so {@code GlobalSearchDialog} can run the exact same matching semantics across row types
 * {@code AbstractTablePanel} doesn't itself know about -- a pure extraction, not a behavior change:
 * every per-tab search still goes through this same class.
 *
 * <p>Query shape: whitespace-separated terms; a term prefixed with {@code -} excludes rows matching it
 * (empty haystack never excluded by this alone); every term is ANDed together (all includes must match,
 * no exclude may match). {@code regex} controls whether each term is compiled as a regex or escaped as
 * a literal ({@link Pattern#quote}); an invalid regex term falls back to literal rather than throwing.
 */
final class SearchQuery {

    private final List<Pattern> includes;
    private final List<Pattern> excludes;

    private SearchQuery(List<Pattern> includes, List<Pattern> excludes) {
        this.includes = includes;
        this.excludes = excludes;
    }

    static SearchQuery parse(String raw, boolean regex, boolean caseSensitive) {
        List<Pattern> includes = new ArrayList<>();
        List<Pattern> excludes = new ArrayList<>();
        int flags = caseSensitive ? 0 : (Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
        for (String tok : raw.trim().split("\\s+")) {
            if (tok.isEmpty()) {
                continue;
            }
            boolean exclude = tok.length() > 1 && tok.charAt(0) == '-';
            String term = exclude ? tok.substring(1) : tok;
            if (term.isEmpty()) {
                continue;
            }
            (exclude ? excludes : includes).add(compile(term, regex, flags));
        }
        return new SearchQuery(includes, excludes);
    }

    /** True when this query has no terms at all (every row passes, same as "search box empty"). */
    boolean isEmpty() {
        return includes.isEmpty() && excludes.isEmpty();
    }

    /** True when {@code haystack} matches every include term and no exclude term. An empty query
     * always matches (nothing to filter on). */
    boolean matches(String haystack) {
        if (isEmpty()) {
            return true;
        }
        for (Pattern p : includes) {
            if (!p.matcher(haystack).find()) {
                return false;
            }
        }
        for (Pattern p : excludes) {
            if (p.matcher(haystack).find()) {
                return false;
            }
        }
        return true;
    }

    private static Pattern compile(String term, boolean regex, int flags) {
        try {
            return Pattern.compile(regex ? term : Pattern.quote(term), flags);
        } catch (PatternSyntaxException e) {
            return Pattern.compile(Pattern.quote(term), flags);
        }
    }
}
