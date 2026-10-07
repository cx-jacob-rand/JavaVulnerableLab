package org.cysecurity.cspf.jvl.sqli;

import junit.framework.TestCase;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Pattern;

/**
 * Tests to verify that Messages.jsp is protected against Second-Order SQL Injection (CWE-89).
 *
 * Taint flow being tested:
 *   SOURCE: rs.getString("username") in LoginValidator.processRequest (line 60) →
 *           stored into HttpSession as the "user" attribute.
 *   SINK (fixed): PreparedStatement with a bind parameter in Messages.jsp (line 16) —
 *           the session "user" attribute is no longer concatenated directly into the
 *           SQL SELECT query executed via Statement.executeQuery(String).
 *
 * Attack scenario prevented:
 *   An attacker registers with a username containing SQL payload, e.g.:
 *       ' OR '1'='1
 *   LoginValidator stores this value verbatim into the database and into the session.
 *   When the attacker later views Messages.jsp, the session attribute is retrieved and
 *   — in the unfixed version — concatenated directly into:
 *       "select * from UserMessages where recipient='" + session.getAttribute("user") + "'"
 *   resulting in the injected query:
 *       select * from UserMessages where recipient='' OR '1'='1'
 *   This would return ALL messages from all users.
 *
 * The fix replaces the vulnerable pattern:
 *   Statement stmt = con.createStatement();
 *   rs = stmt.executeQuery("select * from UserMessages where recipient='" +
 *                           session.getAttribute("user") + "'");
 * with the safe parameterized pattern:
 *   PreparedStatement stmt = con.prepareStatement(
 *       "select * from UserMessages where recipient=?");
 *   stmt.setString(1, (String) session.getAttribute("user"));
 *   rs = stmt.executeQuery();
 */
public class MessagesSecondOrderSqlInjectionTest extends TestCase {

    /** Path to the vulnerable JSP relative to the Maven project root. */
    private static final String JSP_RELATIVE_PATH =
            "src/main/webapp/vulnerability/Messages.jsp";

    private String jspContent;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        File jspFile = new File(JSP_RELATIVE_PATH);
        assertTrue(
                "Messages.jsp must exist at " + jspFile.getAbsolutePath(),
                jspFile.exists());
        jspContent = new String(Files.readAllBytes(Paths.get(jspFile.getAbsolutePath())));
    }

    // -----------------------------------------------------------------------
    // 1. Unsafe Statement import replaced by PreparedStatement import
    // -----------------------------------------------------------------------

    /**
     * Verify that Messages.jsp no longer imports java.sql.Statement.
     * Statement is the class that allows raw SQL string construction and
     * is the enabler of the second-order injection in the original code.
     */
    public void testStatementImportRemoved() {
        assertFalse(
                "Messages.jsp must not import java.sql.Statement; "
                + "Statement allows raw SQL string concatenation which enables SQL injection.",
                jspContent.contains("import=\"java.sql.Statement\"")
                || jspContent.contains("import java.sql.Statement"));
    }

    /**
     * Verify that Messages.jsp imports java.sql.PreparedStatement.
     * PreparedStatement is the JDBC API that supports parameterized queries,
     * which fully separate the SQL code from user-supplied (or DB-supplied) data.
     */
    public void testPreparedStatementImported() {
        assertTrue(
                "Messages.jsp must import java.sql.PreparedStatement "
                + "to use parameterized queries.",
                jspContent.contains("PreparedStatement"));
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
                "Messages.jsp must call con.prepareStatement(...) "
                + "instead of con.createStatement().",
                jspContent.contains("con.prepareStatement("));
    }

    /**
     * Verify that con.createStatement() is no longer called, since that API
     * does not support bind parameters and was used in the vulnerable code.
     */
    public void testCreateStatementNotUsed() {
        assertFalse(
                "Messages.jsp must not call con.createStatement() "
                + "since that API does not support bind parameters and enables SQL injection.",
                jspContent.contains("con.createStatement()"));
    }

    // -----------------------------------------------------------------------
    // 3. SQL query uses '?' placeholder instead of string concatenation
    // -----------------------------------------------------------------------

    /**
     * Verify that the SQL SELECT query uses a '?' bind parameter for the
     * 'recipient' column instead of directly embedding the session attribute
     * value into the query string.
     *
     * Safe pattern:   prepareStatement("select * from UserMessages where recipient=?")
     * Unsafe pattern: "select * from UserMessages where recipient='" +
     *                  session.getAttribute("user") + "'"
     */
    public void testSqlQueryUsesParameterPlaceholder() {
        assertTrue(
                "The SQL SELECT query in Messages.jsp must use a '?' bind parameter "
                + "instead of embedding session.getAttribute(\"user\") directly in the query string.",
                jspContent.contains("recipient=?"));
    }

    // -----------------------------------------------------------------------
    // 4. Session attribute bound via setString(), not concatenated
    // -----------------------------------------------------------------------

    /**
     * Verify that the session "user" attribute is bound to the PreparedStatement
     * via setString() rather than being concatenated into the SQL string.
     * This is the key control that prevents second-order injection:
     * even if the username stored in the DB contains SQL metacharacters,
     * setString() passes it as a literal data value, not as SQL syntax.
     */
    public void testSessionUserBoundWithSetString() {
        assertTrue(
                "Messages.jsp must bind the session 'user' attribute using stmt.setString(1, ...) "
                + "on the PreparedStatement rather than concatenating it into the SQL string.",
                jspContent.contains("stmt.setString(1,") && jspContent.contains("getAttribute(\"user\")"));
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
                "Messages.jsp must call stmt.executeQuery() with no arguments "
                + "(PreparedStatement form) rather than passing the SQL string directly.",
                jspContent.contains("stmt.executeQuery()"));
    }

    // -----------------------------------------------------------------------
    // 6. Original vulnerable string-concatenation patterns removed
    // -----------------------------------------------------------------------

    /**
     * Verify that the original vulnerable pattern — concatenating
     * session.getAttribute("user") directly into the SQL query string
     * passed to executeQuery() — no longer exists.
     *
     * The original sink was:
     *   stmt.executeQuery("select * from UserMessages where recipient='"
     *       + session.getAttribute("user") + "'")
     */
    public void testNoSessionAttributeConcatenationInExecuteQuery() {
        Pattern unsafePattern = Pattern.compile(
                "executeQuery\\s*\\(\\s*\"[^\"]*\"\\s*\\+");
        assertFalse(
                "Messages.jsp must not concatenate any value directly into an "
                + "executeQuery() call. Use PreparedStatement with a bind parameter instead.",
                unsafePattern.matcher(jspContent).find());
    }

    /**
     * Verify that the known-vulnerable query fragment that embeds the session
     * "user" attribute via string concatenation is absent.
     *
     * Unsafe fragments that must NOT appear:
     *   recipient='" + session.getAttribute("user") + "'
     *   recipient='" +session.getAttribute("user")+ "'
     *   recipient='"+session.getAttribute("user")+"'
     */
    public void testNoRecipientConcatenationTokens() {
        String[] dangerousTokens = {
            "recipient='\"",
            "recipient=\"'\"",
            "recipient=\" +",
            "recipient=\"+",
            "\" + session.getAttribute",
            "\"+session.getAttribute",
            "getAttribute(\"user\") +",
            "getAttribute(\"user\")+",
            "+ session.getAttribute(\"user\")",
            "+session.getAttribute(\"user\")"
        };
        for (String token : dangerousTokens) {
            assertFalse(
                    "Messages.jsp must not contain the SQL concatenation token: [" + token + "]",
                    jspContent.contains(token));
        }
    }

    /**
     * Regression check: verify that classic SQL injection payload delimiters
     * that would have been executable via the original second-order attack are
     * not embedded literally inside any SQL string in the JSP.
     *
     * For example, the payload " OR '1'='1 " would have been injected via a
     * registered username. This test confirms that direct SQL-operator tokens
     * are not present inside the query string literals of this file.
     */
    public void testNoSqlInjectionPayloadInQueryString() {
        // These tokens should never appear inside the SQL query string literals
        String[] dangerousQueryTokens = {
            "recipient=\" +",
            "recipient=\"+",
            "\" + session",
            "\"+session"
        };
        for (String token : dangerousQueryTokens) {
            assertFalse(
                    "Messages.jsp SQL query string must not contain the concatenation token: [" + token + "]",
                    jspContent.contains(token));
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
                "Messages.jsp must declare the statement variable as "
                + "PreparedStatement, not the raw Statement interface.",
                jspContent.contains("PreparedStatement stmt"));
    }

    /**
     * Verify that the SQL query template string itself is static (no runtime
     * concatenation within it). This confirms the fix uses the canonical
     * constant-template PreparedStatement pattern recognized by SAST engines.
     *
     * The expected static template is:
     *   "select * from UserMessages where recipient=?"
     */
    public void testSqlQueryTemplateIsStaticString() {
        assertTrue(
                "Messages.jsp must use a static SQL query string with a '?' placeholder: "
                + "\"select * from UserMessages where recipient=?\"",
                jspContent.contains("\"select * from UserMessages where recipient=?\""));
    }
}
