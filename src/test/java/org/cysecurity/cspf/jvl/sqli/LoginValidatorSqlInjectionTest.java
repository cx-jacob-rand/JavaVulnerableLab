package org.cysecurity.cspf.jvl.sqli;

import junit.framework.TestCase;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Pattern;

/**
 * Tests to verify that LoginValidator.java is protected against SQL Injection (CWE-89)
 * via the "username" and "password" request parameters.
 *
 * Taint flow being tested:
 *   SOURCE: request.getParameter("password") at line 44 (processRequest method)
 *           request.getParameter("username") at line 43 (processRequest method)
 *   SINK (fixed): PreparedStatement with bound parameters — no longer a
 *           string-concatenated SELECT statement executed via Statement.executeQuery().
 *
 * The fix replaces:
 *   Statement stmt = con.createStatement();
 *   rs = stmt.executeQuery("select * from users where username='" + user + "' and password='" + pass + "'");
 * with:
 *   PreparedStatement stmt = con.prepareStatement("select * from users where username=? and password=?");
 *   stmt.setString(1, user);
 *   stmt.setString(2, pass);
 *   rs = stmt.executeQuery();
 */
public class LoginValidatorSqlInjectionTest extends TestCase {

    /** Path to the servlet source file relative to the Maven project root. */
    private static final String SOURCE_RELATIVE_PATH =
            "src/main/java/org/cysecurity/cspf/jvl/controller/LoginValidator.java";

    private String sourceContent;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        File sourceFile = new File(SOURCE_RELATIVE_PATH);
        assertTrue(
                "LoginValidator.java must exist at " + sourceFile.getAbsolutePath(),
                sourceFile.exists());
        sourceContent = new String(Files.readAllBytes(Paths.get(sourceFile.getAbsolutePath())));
    }

    // -----------------------------------------------------------------------
    // 1. Unsafe Statement import removed, PreparedStatement import added
    // -----------------------------------------------------------------------

    /**
     * Verify that LoginValidator.java no longer imports java.sql.Statement.
     * Statement is used with unsafe string concatenation queries and must be
     * replaced by PreparedStatement to prevent SQL injection.
     */
    public void testStatementImportRemoved() {
        assertFalse(
                "LoginValidator.java must not import java.sql.Statement; "
                + "Statement allows raw SQL string concatenation which enables SQL injection.",
                sourceContent.contains("import java.sql.Statement"));
    }

    /**
     * Verify that LoginValidator.java imports java.sql.PreparedStatement.
     * PreparedStatement is the JDBC API that supports parameterized queries,
     * which fully separate the SQL code from user-supplied data.
     */
    public void testPreparedStatementImported() {
        assertTrue(
                "LoginValidator.java must import java.sql.PreparedStatement "
                + "to use parameterized queries.",
                sourceContent.contains("import java.sql.PreparedStatement"));
    }

    // -----------------------------------------------------------------------
    // 2. con.prepareStatement() used instead of con.createStatement()
    // -----------------------------------------------------------------------

    /**
     * Verify that con.prepareStatement() is called, confirming the switch from
     * the vulnerable Statement API to the safe PreparedStatement API.
     */
    public void testPrepareStatementUsed() {
        assertTrue(
                "LoginValidator.java must call con.prepareStatement(...) "
                + "instead of con.createStatement().",
                sourceContent.contains("con.prepareStatement("));
    }

    /**
     * Verify that con.createStatement() is no longer called, since that API
     * does not support bind parameters and was used in the vulnerable code.
     */
    public void testCreateStatementNotUsed() {
        assertFalse(
                "LoginValidator.java must not call con.createStatement() "
                + "since that API does not support bind parameters and enables SQL injection.",
                sourceContent.contains("con.createStatement()"));
    }

    // -----------------------------------------------------------------------
    // 3. SQL query uses '?' placeholders instead of string concatenation
    // -----------------------------------------------------------------------

    /**
     * Verify that the SQL SELECT query uses '?' bind parameters for both the
     * 'username' and 'password' columns instead of directly embedding user
     * input into the query string.
     *
     * Safe pattern:   prepareStatement("select * from users where username=? and password=?")
     * Unsafe pattern: "select * from users where username='" + user + "' and password='" + pass + "'"
     */
    public void testSqlQueryUsesParameterPlaceholders() {
        assertTrue(
                "The SQL SELECT query in LoginValidator.java must use '?' bind parameters "
                + "instead of embedding 'user' or 'pass' directly in the query string.",
                sourceContent.contains("username=?") && sourceContent.contains("password=?"));
    }

    // -----------------------------------------------------------------------
    // 4. User input is bound via setString(), not concatenated
    // -----------------------------------------------------------------------

    /**
     * Verify that the 'user' (username) parameter is bound via setString(1, user)
     * on the PreparedStatement rather than concatenated into the SQL string.
     */
    public void testUsernameBoundWithSetString() {
        assertTrue(
                "LoginValidator.java must bind 'user' using stmt.setString(1, user) "
                + "on the PreparedStatement.",
                sourceContent.contains("setString(1, user)"));
    }

    /**
     * Verify that the 'pass' (password) parameter is bound via setString(2, pass)
     * on the PreparedStatement rather than concatenated into the SQL string.
     */
    public void testPasswordBoundWithSetString() {
        assertTrue(
                "LoginValidator.java must bind 'pass' using stmt.setString(2, pass) "
                + "on the PreparedStatement.",
                sourceContent.contains("setString(2, pass)"));
    }

    // -----------------------------------------------------------------------
    // 5. executeQuery() called with no arguments (PreparedStatement form)
    // -----------------------------------------------------------------------

    /**
     * Verify that executeQuery() is called with no SQL string argument
     * (PreparedStatement form), not the Statement.executeQuery(String) form
     * that accepts a raw SQL string and would allow re-introduction of injection.
     */
    public void testExecuteQueryCalledWithoutArgument() {
        assertTrue(
                "LoginValidator.java must call stmt.executeQuery() with no arguments "
                + "(PreparedStatement form) rather than passing the SQL string directly.",
                sourceContent.contains("stmt.executeQuery()"));
    }

    // -----------------------------------------------------------------------
    // 6. Original vulnerable string-concatenation patterns removed
    // -----------------------------------------------------------------------

    /**
     * Verify that the original vulnerable pattern — directly concatenating 'user'
     * into a SELECT query string via executeQuery(String) — no longer exists.
     * The unsafe pattern was: stmt.executeQuery("... username='" + user + "' ...")
     */
    public void testNoUsernameConcatenationInExecuteQuery() {
        Pattern unsafeUsernamePattern = Pattern.compile(
                "executeQuery\\s*\\(\\s*\"[^\"]*\"\\s*\\+\\s*user");
        assertFalse(
                "LoginValidator.java must not concatenate 'user' directly into an "
                + "executeQuery() call. Use PreparedStatement with a bind parameter instead.",
                unsafeUsernamePattern.matcher(sourceContent).find());
    }

    /**
     * Verify that the original vulnerable pattern — directly concatenating 'pass'
     * into a SELECT query string via executeQuery(String) — no longer exists.
     * The unsafe pattern was: stmt.executeQuery("... password='" + pass + "'")
     */
    public void testNoPasswordConcatenationInExecuteQuery() {
        Pattern unsafePassPattern = Pattern.compile(
                "executeQuery\\s*\\(\\s*\"[^\"]*\"\\s*[^)]*\\+\\s*pass");
        assertFalse(
                "LoginValidator.java must not concatenate 'pass' directly into an "
                + "executeQuery() call. Use PreparedStatement with a bind parameter instead.",
                unsafePassPattern.matcher(sourceContent).find());
    }

    /**
     * Regression check: verify that known SQL injection payload token patterns
     * derived from the original vulnerable concatenation are no longer present.
     */
    public void testNoSqlInjectionConcatenationTokens() {
        String[] dangerousTokens = {
            "username='\"",
            "username=\" +",
            "password='\"",
            "password=\" +",
            "\"+ user",
            "\" + user",
            "\"+pass",
            "\" + pass",
            "'+user+'",
            "'+pass+'"
        };
        for (String token : dangerousTokens) {
            assertFalse(
                    "LoginValidator.java must not contain the SQL concatenation token: [" + token + "]",
                    sourceContent.contains(token));
        }
    }

    // -----------------------------------------------------------------------
    // 7. Structural sanity checks
    // -----------------------------------------------------------------------

    /**
     * Verify that the PreparedStatement variable type is declared (not the
     * broader Statement type), ensuring the variable is correctly typed for
     * the parameterized-query API.
     */
    public void testPreparedStatementVariableDeclared() {
        assertTrue(
                "LoginValidator.java must declare the statement variable as "
                + "PreparedStatement, not the raw Statement interface.",
                sourceContent.contains("PreparedStatement stmt"));
    }
}
