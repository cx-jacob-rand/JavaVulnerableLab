package org.cysecurity.cspf.jvl.csrf;

import junit.framework.TestCase;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Pattern;

/**
 * Tests to verify that changepassword.jsp is protected against Second-Order SQL
 * Injection (CWE-89) by using a parameterized PreparedStatement rather than
 * string concatenation.
 *
 * The taint flow being tested:
 *   SOURCE (adminlogin.jsp, line 19-22): On admin login, rs.getString("id") reads the
 *           userid from the database result set and stores it in the HTTP session via
 *           session.setAttribute("userid", ...). An attacker who previously injected data
 *           into the users table can poison this session attribute.
 *   INTERMEDIATE (changepassword.jsp, line 15): session.getAttribute("userid").toString()
 *           retrieves the potentially-tainted value and assigns it to the local variable
 *           "id".
 *   SINK (fixed, changepassword.jsp, line 40): The UPDATE statement now uses a
 *           PreparedStatement with '?' bind parameters so neither "pass" nor "id"
 *           can alter the SQL structure.
 */
public class ChangePasswordSqlInjectionTest extends TestCase {

    /** Relative path to the JSP file from the Maven project root. */
    private static final String JSP_RELATIVE_PATH =
            "src/main/webapp/vulnerability/csrf/changepassword.jsp";

    private String jspContent;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        File jspFile = new File(JSP_RELATIVE_PATH);
        assertTrue(
                "JSP file must exist at " + jspFile.getAbsolutePath(),
                jspFile.exists());
        jspContent = new String(Files.readAllBytes(Paths.get(jspFile.getAbsolutePath())));
    }

    /**
     * Verify that the JSP no longer imports java.sql.Statement.
     * Statement is the class used with unsafe string-concatenated queries and
     * must be replaced by PreparedStatement.
     */
    public void testStatementImportRemoved() {
        assertFalse(
                "changepassword.jsp must not import java.sql.Statement; "
                + "Statement allows raw SQL string concatenation which enables SQL injection.",
                jspContent.contains("import=\"java.sql.Statement\"")
                || jspContent.contains("import java.sql.Statement"));
    }

    /**
     * Verify that the JSP imports java.sql.PreparedStatement.
     * PreparedStatement is the JDBC API that enables parameterized queries.
     */
    public void testPreparedStatementImported() {
        assertTrue(
                "changepassword.jsp must import java.sql.PreparedStatement "
                + "to use parameterized queries.",
                jspContent.contains("PreparedStatement"));
    }

    /**
     * Verify that the SQL UPDATE query uses '?' placeholders for both the
     * 'password' column value and the 'id' condition instead of directly
     * embedding user-controlled values into the query string.
     *
     * Safe pattern:   prepareStatement("UPDATE users SET password=? WHERE id=?")
     * Unsafe pattern: "Update users set password='" + pass + "' where id=" + id
     */
    public void testSqlQueryUsesParameterPlaceholders() {
        assertTrue(
                "The SQL UPDATE query in changepassword.jsp must use '?' bind parameters "
                + "instead of embedding 'pass' or 'id' directly in the query string.",
                jspContent.contains("password=?") && jspContent.contains("id=?"));
    }

    /**
     * Verify that the 'pass' parameter is bound via setString() rather than
     * concatenated into the query string.
     */
    public void testPassBoundWithSetString() {
        assertTrue(
                "changepassword.jsp must bind 'pass' using stmt.setString(1, pass) "
                + "on the PreparedStatement.",
                jspContent.contains("setString(1, pass)"));
    }

    /**
     * Verify that the 'id' value (sourced from session, originally from the DB)
     * is bound via a setter rather than concatenated into the WHERE clause.
     * This is the core protection against the Second-Order SQL Injection vector:
     * an attacker cannot inject SQL via a poisoned userid stored in the session.
     */
    public void testIdBoundWithSetter() {
        // The id may be bound as setString or setInt/setLong depending on the column type.
        assertTrue(
                "changepassword.jsp must bind 'id' using a PreparedStatement setter "
                + "(setString(2, id), setInt(2, ...), or setLong(2, ...)).",
                jspContent.contains("setString(2, id)")
                || jspContent.contains("setInt(2,")
                || jspContent.contains("setLong(2,"));
    }

    /**
     * Verify that executeUpdate() is called with no SQL string argument
     * (PreparedStatement form), not the Statement form that accepts a SQL string.
     */
    public void testExecuteUpdateCalledWithoutArgument() {
        assertTrue(
                "changepassword.jsp must call executeUpdate() with no arguments "
                + "(PreparedStatement form) rather than passing the SQL string directly.",
                jspContent.contains("stmt.executeUpdate()"));
    }

    /**
     * Verify that the 'pass' parameter is NOT directly concatenated into any
     * SQL string in the file. This catches the original vulnerable pattern:
     *   "Update users set password='" + pass + "' where id=" + id
     */
    public void testNoDirectPassConcatenationInSql() {
        Pattern unsafePassPattern = Pattern.compile(
                "(executeUpdate|executeQuery)\\s*\\(\\s*\"[^\"]*\"\\s*\\+\\s*pass");
        assertFalse(
                "changepassword.jsp must not concatenate 'pass' directly into an "
                + "executeUpdate() or executeQuery() call. "
                + "Use PreparedStatement with a bind parameter instead.",
                unsafePassPattern.matcher(jspContent).find());
    }

    /**
     * Verify that the 'id' value is NOT directly concatenated into any
     * SQL string in the file. This is the primary guard against Second-Order SQL
     * Injection: the 'id' originates from session data that was read from the DB
     * during admin login and could itself carry injected SQL payload.
     */
    public void testNoDirectIdConcatenationInSql() {
        Pattern unsafeIdPattern = Pattern.compile(
                "(executeUpdate|executeQuery)\\s*\\(\\s*\"[^\"]*\"\\s*\\+\\s*id");
        assertFalse(
                "changepassword.jsp must not concatenate 'id' directly into an "
                + "executeUpdate() or executeQuery() call. "
                + "Use PreparedStatement with a bind parameter instead.",
                unsafeIdPattern.matcher(jspContent).find());
    }

    /**
     * Regression: verify that none of the classic SQL injection string-building
     * tokens that would reconstruct the vulnerable pattern appear anywhere in
     * the JSP.
     */
    public void testNoSqlInjectionConcatenationTokens() {
        String[] dangerousTokens = {
            "password='\"+",
            "password='\" +",
            "\"+ pass",
            "\" + pass",
            "id=\"+id",
            "id=\" + id",
            "where id=\"+",
            "where id=\" +"
        };
        for (String token : dangerousTokens) {
            assertFalse(
                    "changepassword.jsp must not contain the SQL concatenation token: [" + token + "]",
                    jspContent.contains(token));
        }
    }

    /**
     * Verify that con.prepareStatement() is called (not con.createStatement()),
     * confirming the switch from the vulnerable Statement API to PreparedStatement.
     */
    public void testPrepareStatementUsed() {
        assertTrue(
                "changepassword.jsp must call con.prepareStatement(...) "
                + "instead of con.createStatement().",
                jspContent.contains("con.prepareStatement("));

        assertFalse(
                "changepassword.jsp must not call con.createStatement() "
                + "since that API does not support bind parameters.",
                jspContent.contains("con.createStatement()"));
    }

    /**
     * Verify the fixed SQL template string uses the correct structure.
     * The UPDATE statement must be a static string with no dynamic parts.
     */
    public void testSqlTemplateIsStaticString() {
        // The full safe SQL template should appear as a static literal
        assertTrue(
                "changepassword.jsp must contain the static parameterized SQL template "
                + "\"UPDATE users SET password=? WHERE id=?\".",
                jspContent.contains("UPDATE users SET password=? WHERE id=?")
                || jspContent.contains("update users set password=? where id=?")
                || jspContent.contains("UPDATE users set password=? WHERE id=?")
                || jspContent.contains("UPDATE users SET password=? where id=?"));
    }
}
