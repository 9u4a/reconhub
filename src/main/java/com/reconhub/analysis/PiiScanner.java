package com.reconhub.analysis;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.core.DataStore;
import com.reconhub.model.Finding;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive PII detection (incl. Korea-specific identifiers) on captured response bodies. Uses regex
 * plus validation (Luhn for cards, checksum/date for Korean RRN) to keep false positives low.
 * Matched values are treated as sensitive (masked in reports).
 */
public final class PiiScanner {

    private static final int MAX_PER_RULE = 25;

    // Korean Resident Registration Number: YYMMDD-Gxxxxxx
    private static final Pattern RRN =
            Pattern.compile("(?<![0-9])(\\d{6})-?([1-4]\\d{6})(?![0-9])");
    // Korean mobile phone: 01x-xxxx-xxxx (or 3-digit middle)
    private static final Pattern PHONE_KR =
            Pattern.compile("(?<![0-9])01[016789]-?\\d{3,4}-?\\d{4}(?![0-9])");
    // Candidate payment card: 13-19 digits, optionally split by space/dash. Decimal points are
    // excluded on both sides so parts of longer numbers/decimals aren't picked up.
    private static final Pattern CARD =
            Pattern.compile("(?<![0-9.])(?:\\d[ -]?){13,19}(?![0-9.])");

    private final DataStore store;

    public PiiScanner(DataStore store) {
        this.store = store;
    }

    /** @return number of newly discovered PII findings in this body. */
    public int scan(String body, String url, HttpRequestResponse rr) {
        if (body == null || body.isEmpty()) {
            return 0;
        }
        int newCount = 0;
        newCount += scanRrn(body, url, rr);
        newCount += scanCard(body, url, rr);
        newCount += scanPhone(body, url, rr);
        return newCount;
    }

    private int scanRrn(String body, String url, HttpRequestResponse rr) {
        Matcher m = RRN.matcher(body);
        int hits = 0;
        int found = 0;
        while (m.find() && hits < MAX_PER_RULE) {
            hits++;
            String digits = (m.group(1) + m.group(2));
            if (validRrn(digits)) {
                if (record("Korean RRN (주민등록번호)", Finding.Severity.HIGH, m.group(), url, rr)) {
                    found++;
                }
            }
        }
        return found;
    }

    private int scanCard(String body, String url, HttpRequestResponse rr) {
        Matcher m = CARD.matcher(body);
        int hits = 0;
        int found = 0;
        while (m.find() && hits < MAX_PER_RULE) {
            hits++;
            String digits = m.group().replaceAll("[ -]", "");
            if (isPlausibleCard(digits)) {
                if (record("Payment card number", Finding.Severity.HIGH, m.group().trim(),
                        url, rr)) {
                    found++;
                }
            }
        }
        return found;
    }

    private int scanPhone(String body, String url, HttpRequestResponse rr) {
        Matcher m = PHONE_KR.matcher(body);
        int hits = 0;
        int found = 0;
        while (m.find() && hits < MAX_PER_RULE) {
            hits++;
            if (record("Korean phone number", Finding.Severity.LOW, m.group(), url, rr)) {
                found++;
            }
        }
        return found;
    }

    private boolean record(String type, Finding.Severity sev, String match, String url,
                           HttpRequestResponse rr) {
        Finding f = new Finding(type, sev, match, url, "", true);
        f.setMessages(rr);
        return store.recordFinding(f);
    }

    // ---- validation -----------------------------------------------------

    /**
     * A number is reported as a card only when it has a plausible length, passes Luhn, matches a
     * known network's BIN range, and isn't an obviously synthetic run (all-same / sequential). The
     * brand check is what removes most false positives: random Luhn-valid numbers rarely fall in a
     * real BIN range.
     */
    static boolean isPlausibleCard(String d) {
        int len = d.length();
        if (len != 13 && len != 14 && len != 15 && len != 16 && len != 19) {
            return false;
        }
        return luhn(d) && brandKnown(d) && !allSameDigit(d) && !isSequential(d);
    }

    /** Matches the leading digits/length against major card networks' issuer ranges. */
    static boolean brandKnown(String d) {
        int len = d.length();
        int p2 = Integer.parseInt(d.substring(0, 2));
        int p3 = Integer.parseInt(d.substring(0, 3));
        int p4 = Integer.parseInt(d.substring(0, 4));

        // Visa
        if (d.charAt(0) == '4' && (len == 13 || len == 16 || len == 19)) {
            return true;
        }
        // Mastercard: 51-55, or 2221-2720 (len 16)
        if (len == 16 && ((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720))) {
            return true;
        }
        // American Express: 34/37 (len 15)
        if (len == 15 && (p2 == 34 || p2 == 37)) {
            return true;
        }
        // Discover: 6011, 65, 644-649 (len 16 or 19)
        if ((len == 16 || len == 19)
                && (d.startsWith("6011") || p2 == 65 || (p3 >= 644 && p3 <= 649))) {
            return true;
        }
        // Diners Club: 36, 38, 300-305 (len 14)
        if (len == 14 && (p2 == 36 || p2 == 38 || (p3 >= 300 && p3 <= 305))) {
            return true;
        }
        // JCB: 3528-3589 (len 16)
        return len == 16 && p4 >= 3528 && p4 <= 3589;
    }

    private static boolean allSameDigit(String d) {
        for (int i = 1; i < d.length(); i++) {
            if (d.charAt(i) != d.charAt(0)) {
                return false;
            }
        }
        return true;
    }

    /** True for strictly ascending/descending consecutive-digit runs (e.g. 123456…, 9876…). */
    private static boolean isSequential(String d) {
        boolean asc = true;
        boolean desc = true;
        for (int i = 1; i < d.length(); i++) {
            int diff = (d.charAt(i) - '0') - (d.charAt(i - 1) - '0');
            if (diff != 1) {
                asc = false;
            }
            if (diff != -1) {
                desc = false;
            }
        }
        return asc || desc;
    }

    /** Luhn (mod-10) checksum for card numbers. */
    static boolean luhn(String digits) {
        int sum = 0;
        boolean alt = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int d = digits.charAt(i) - '0';
            if (alt) {
                d *= 2;
                if (d > 9) {
                    d -= 9;
                }
            }
            sum += d;
            alt = !alt;
        }
        return sum % 10 == 0;
    }

    /** Korean RRN: 13 digits, valid MMDD, and the standard weighted checksum. */
    static boolean validRrn(String d) {
        if (d.length() != 13) {
            return false;
        }
        int month = Integer.parseInt(d.substring(2, 4));
        int day = Integer.parseInt(d.substring(4, 6));
        if (month < 1 || month > 12 || day < 1 || day > 31) {
            return false;
        }
        int[] w = {2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5};
        int sum = 0;
        for (int i = 0; i < 12; i++) {
            sum += (d.charAt(i) - '0') * w[i];
        }
        int check = (11 - (sum % 11)) % 10;
        return check == (d.charAt(12) - '0');
    }
}
