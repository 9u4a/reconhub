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
 * Regression guard for catastrophic-backtracking risk across every rule in {@code interesting.json}
 * (the "signature" rules -- {@link PatternRegistry#signatureRules()}), each run against adversarial
 * input on a daemon thread with a timeout ({@code Matcher} can't be interrupted). This is a direct
 * port of the 0.35.0 P7 scratchpad check -- the one that caught the real unbounded-{@code .*} bug in
 * the "SQL Error" rule during that round, so it's the highest-value regression guard in this suite.
 * Runs against the live classpath resource, so a rule added to interesting.json later is covered
 * automatically without touching this file.
 */
class PatternRegistryAdversarialTest {

    private static final PatternRegistry REGISTRY = PatternRegistry.load();

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
     * One dynamic test per (adversarial sample x signature rule) pair, so a hang or newly-introduced
     * catastrophic-backtracking regex is reported against the exact rule name responsible, not buried
     * in one big loop.
     */
    @TestFactory
    Stream<DynamicTest> everySignatureRuleSurvivesAdversarialInput() {
        List<DynamicTest> tests = new ArrayList<>();
        String[][] adversarial = {
                {"wordrun", "a".repeat(1_000_000)},
                {"warning-run", "Warning: dense minified js text with no newline ".repeat(20_000)},
                {"exceptionrun", "a.b.c.dException".repeat(60_000)},
        };
        for (String[] sample : adversarial) {
            String label = sample[0];
            String body = sample[1];
            for (PatternRegistry.SecretRule rule : REGISTRY.signatureRules()) {
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
        for (PatternRegistry.SecretRule r : REGISTRY.signatureRules()) {
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
