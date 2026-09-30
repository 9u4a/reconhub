package com.reconhub.analysis;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Regression guard for catastrophic-backtracking risk across every {@link PatternRegistry.SecretRule}
 * -- {@code interesting.json}/{@code secrets.json}/{@code authz.json} (via {@link
 * PatternRegistry#signatureRules()}/{@link PatternRegistry#secretRules()}/{@link
 * PatternRegistry#authzRules()}) -- each run against adversarial input on a daemon thread with a
 * timeout ({@code Matcher} can't be interrupted). This is a direct port of the 0.35.0 P7 scratchpad
 * check -- the one that caught the real unbounded-{@code .*} bug in the "SQL Error" rule during that
 * round, so it's the highest-value regression guard in this suite.
 *
 * <p><b>0.41.2: widened from {@code signatureRules()} alone to all three {@code SecretRule} lists</b> --
 * {@code secretRules()} (every secret pattern that scans every response body) had never once been
 * checked for this, and that's exactly how "S3 Bucket URL"/"Azure Blob URL" (unanchored unbounded spans,
 * the same "wordrun" shape this suite already knew to test for) shipped unnoticed. "Java Exception"/
 * ".NET Stack Trace" (in {@code interesting.json}, so technically always in scope) went unnoticed for a
 * different reason: none of the 3 canned adversarial samples happened to contain their specific trigger
 * keyword ("java."/"System." repeated) -- the {@code javaExceptionRun}/{@code dotNetDotRun} samples
 * below close that gap. Runs against the live classpath resources, so a rule added later is covered
 * automatically without touching this file.
 */
class PatternRegistryAdversarialTest {

    private static final PatternRegistry REGISTRY = PatternRegistry.load();

    /** {@code signatureRules() + secretRules() + authzRules()} -- every {@code SecretRule}, regardless
     * of which JSON file it came from. */
    private static List<PatternRegistry.SecretRule> allSecretRules() {
        List<PatternRegistry.SecretRule> all = new ArrayList<>();
        all.addAll(REGISTRY.signatureRules());
        all.addAll(REGISTRY.secretRules());
        all.addAll(REGISTRY.authzRules());
        return all;
    }

    @Test
    void patternRegistryLoadsWithNoErrors() {
        assertTrue(REGISTRY.loadErrors().isEmpty(), "load errors: " + REGISTRY.loadErrors());
    }

    @Test
    void javaStackTraceStillMatchesRealTraces() {
        Pattern javaStack = findRule("Java Stack Trace");
        assertNotNull(javaStack, "Java Stack Trace rule must exist");

        String javaTrace = "java.lang.NullPointerException: null\n"
                + "\tat com.foo.Bar.baz(Bar.java:42)\n"
                + "\tat com.foo.Main.main(Main.java:10)\n";
        assertTrue(javaStack.matcher(javaTrace).find(), "real 2-frame Java trace should match");

        String springTrace = "org.springframework.beans.factory.BeanCreationException: Error creating bean\n"
                + "\tat org.springframework.beans.factory.support.AbstractBeanFactory.doGetBean(AbstractBeanFactory.java:320)\n"
                + "\tat org.springframework.beans.factory.support.AbstractBeanFactory.getBean(AbstractBeanFactory.java:199)\n";
        assertTrue(javaStack.matcher(springTrace).find(), "Spring BeanCreationException trace should match");

        assertFalse(javaStack.matcher("This API throws an Exception if the input is invalid.").find(),
                "prose containing 'Exception' should not match");
        assertFalse(javaStack.matcher("\tat foo()\n").find(), "a lone 'at foo()' line should not match");
    }

    @Test
    void phpErrorStillMatchesRealErrors() {
        Pattern phpError = findRule("PHP Error");
        assertNotNull(phpError, "PHP Error rule must exist");

        String phpNotice = "Warning: include(/var/www/html/x.php): failed to open stream: "
                + "No such file or directory in /var/www/html/index.php on line 12";
        assertTrue(phpError.matcher(phpNotice).find(), "real PHP warning should match");

        String phpWin = "Fatal error: Uncaught Error: Call to undefined function foo() in "
                + "C:\\xampp\\htdocs\\index.php on line 5";
        assertTrue(phpError.matcher(phpWin).find(), "Windows-path PHP fatal error should match");
    }

    @Test
    void javaExceptionStillMatchesRealFqcns() {
        // 0.41.2: [\w.$]* -> [\w.$]{0,120} -- must not regress real (deeply-nested, package-qualified)
        // exception class names, only kill the catastrophic-backtracking shape.
        Pattern javaException = findRule("Java Exception");
        assertNotNull(javaException, "Java Exception rule must exist");

        assertTrue(javaException.matcher("java.lang.NullPointerException").find());
        assertTrue(javaException.matcher("javax.persistence.EntityNotFoundException").find());
        assertTrue(javaException.matcher(
                "org.springframework.beans.factory.BeanCreationException").find());
        assertTrue(javaException.matcher("jakarta.validation.ConstraintViolationException").find());
    }

    @Test
    void dotNetStackTraceStillMatchesRealTraces() {
        // 0.41.2: [\w.]+ -> [\w.]{1,120} after "System." -- same regression concern as above.
        Pattern dotnet = findRule(".NET Stack Trace");
        assertNotNull(dotnet, ".NET Stack Trace rule must exist");

        String realTrace = "System.NullReferenceException: Object reference not set to an instance of "
                + "an object.\n   at MyApp.Controllers.HomeController.Index() in "
                + "C:\\src\\HomeController.cs:line 42";
        assertTrue(dotnet.matcher(realTrace).find(), "real .NET stack trace should still match");
    }

    @Test
    void s3AndAzureUrlsStillMatchRealOnes() {
        // 0.41.2: unanchored unbounded prefix -> {1,63} (AWS S3 bucket / DNS label length limits).
        Pattern s3 = findRule("S3 Bucket URL");
        Pattern azure = findRule("Azure Blob URL");
        assertNotNull(s3, "S3 Bucket URL rule must exist");
        assertNotNull(azure, "Azure Blob URL rule must exist");

        assertTrue(s3.matcher("my-bucket.s3.amazonaws.com").find());
        assertTrue(s3.matcher("my-bucket.s3.us-east-1.amazonaws.com").find(), "regional S3 URL");
        assertTrue(azure.matcher("mystorageacct.blob.core.windows.net").find());
    }

    @Test
    void emailAddressStillMatchesRealAddresses() {
        // 0.41.2: local-part [a-zA-Z0-9._%+\-]+ was unanchored AND unbounded -- caught live by the
        // adversarial TestFactory below (the "wordrun" sample, which has no '@' at all, hung for
        // >5000ms) rather than by a hand-written probe first, unlike the other three 0.41.2 fixes.
        // Bounded to RFC 5321's actual 64-octet local-part limit (domain part to RFC 1035's 253-char
        // domain limit, defense in depth).
        Pattern email = findRule("Email Address");
        assertNotNull(email, "Email Address rule must exist");

        assertTrue(email.matcher("user.name+tag@example.co.uk").find());
        assertTrue(email.matcher("simple@example.com").find());
    }

    @Test
    void sqlErrorStillMatchesRealErrors() {
        // The rule whose unbounded .* spans this suite actually caught in 0.35.0 (P7).
        Pattern sqlError = findRule("SQL Error");
        assertNotNull(sqlError, "SQL Error rule must exist");

        String mysqlWarning = "Warning: mysqli_query(): (42000/1064): You have an error in your SQL syntax";
        assertTrue(sqlError.matcher(mysqlWarning).find(), "real mysqli warning should match SQL Error");

        String sqlSyntax = "You have an error in your SQL syntax; check the manual that corresponds to "
                + "your MySQL server version for the right syntax to use";
        assertTrue(sqlError.matcher(sqlSyntax).find(), "real SQL syntax message should match SQL Error");
    }

    /**
     * One dynamic test per (adversarial sample x rule) pair, across all three {@code SecretRule} lists
     * (see {@link #allSecretRules()}), so a hang or newly-introduced catastrophic-backtracking regex is
     * reported against the exact rule name responsible, not buried in one big loop.
     */
    @TestFactory
    Stream<DynamicTest> everySecretRuleSurvivesAdversarialInput() {
        List<DynamicTest> tests = new ArrayList<>();
        String[][] adversarial = {
                {"wordrun", "a".repeat(1_000_000)},
                {"warning-run", "Warning: dense minified js text with no newline ".repeat(20_000)},
                {"exceptionrun", "a.b.c.dException".repeat(60_000)},
                // 0.41.2: neither of these two matched any rule's trigger keyword before, so "Java
                // Exception"/".NET Stack Trace" hung on exactly this shape without any sample catching
                // it -- see RedosProbe.java/RedosProbe3.java in the scratchpad history for the original
                // repro.
                {"java-dotrun", "java.".repeat(200_000)},
                {"dotnet-dotrun", "System.".repeat(200_000)},
        };
        List<PatternRegistry.SecretRule> rules = allSecretRules();
        for (String[] sample : adversarial) {
            String label = sample[0];
            String body = sample[1];
            for (PatternRegistry.SecretRule rule : rules) {
                tests.add(DynamicTest.dynamicTest(label + " / " + rule.name, () -> {
                    long ms = timeWithTimeout(rule.pattern, body, 5000);
                    if (ms < 0) {
                        fail("timed out (>5000ms) -- likely catastrophic backtracking in rule \""
                                + rule.name + "\"");
                    }
                    // 2000ms, not the original 1000ms: the two 0.41.2 samples below are ~1.4MB each
                    // (large enough to force a clear >5000ms hang out of the *unfixed* Java Exception/
                    // .NET Stack Trace regexes), and running every rule against a sample that size
                    // costs a genuinely-fine ~1.2s for some already-bounded rules (e.g. Email Address,
                    // which still does an O(n) unanchored scan even once bounded) -- 5000ms remains the
                    // real signal for catastrophic/quadratic blowup; this is just "acceptably fast",
                    // not "instant".
                    assertTrue(ms < 2000, "rule \"" + rule.name + "\" took " + ms
                            + "ms on adversarial input \"" + label + "\" (expected < 2000ms)");
                }));
            }
        }
        return tests.stream();
    }

    /** {@link PatternRegistry.JsLinkRule} is a different type (no {@code severity}), so it gets its own
     * factory rather than folding into {@link #allSecretRules()} -- covered here for the same insurance
     * reason, even though this round's audit found no vulnerable rule in {@code js-endpoints.json} (the
     * quote delimiter each rule opens/closes with is excluded from its own body character class, which
     * makes the backtracking self-limiting -- see the plan notes for the full reasoning). */
    @TestFactory
    Stream<DynamicTest> everyJsLinkRuleSurvivesAdversarialInput() {
        List<DynamicTest> tests = new ArrayList<>();
        String[][] adversarial = {
                {"wordrun", "a".repeat(1_000_000)},
                {"quote-run", "'/aaaaaaaaaaaaaaaaaaaa".repeat(20_000)},
        };
        for (String[] sample : adversarial) {
            String label = sample[0];
            String body = sample[1];
            for (PatternRegistry.JsLinkRule rule : REGISTRY.jsLinkRules()) {
                tests.add(DynamicTest.dynamicTest(label + " / " + rule.name, () -> {
                    long ms = timeWithTimeout(rule.pattern, body, 5000);
                    if (ms < 0) {
                        fail("timed out (>5000ms) -- likely catastrophic backtracking in rule \""
                                + rule.name + "\"");
                    }
                    assertTrue(ms < 1000, "rule \"" + rule.name + "\" took " + ms
                            + "ms on adversarial input \"" + label + "\" (expected < 1000ms)");
                }));
            }
        }
        return tests.stream();
    }

    private static Pattern findRule(String name) {
        for (PatternRegistry.SecretRule r : allSecretRules()) {
            if (r.name.equals(name)) {
                return r.pattern;
            }
        }
        return null;
    }

    /** Runs the match on a daemon thread with a timeout (Matcher can't be interrupted).
     * @return elapsed ms, or -1 if it didn't finish within timeoutMs. */
    private static long timeWithTimeout(Pattern p, String body, long timeoutMs) throws InterruptedException {
        AtomicBoolean done = new AtomicBoolean(false);
        long[] elapsed = {-1};
        Thread t = new Thread(() -> {
            long start = System.currentTimeMillis();
            Matcher m = p.matcher(body);
            m.find();
            elapsed[0] = System.currentTimeMillis() - start;
            done.set(true);
        });
        t.setDaemon(true);
        t.start();
        t.join(timeoutMs);
        return done.get() ? elapsed[0] : -1;
    }
}
