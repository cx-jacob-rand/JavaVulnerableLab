package org.cysecurity.cspf.jvl.csrf;

import junit.framework.TestCase;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Pattern;

/**
 * Tests to verify that change-info.jsp is protected against Second-Order SQL
 * Injection (CWE-89) by using a parameterized PreparedStatement rather than
 * string concatenation.
 *
 * The taint flow being tested:
 *   SOURCE: session.getAttribute("userid") [value originally stored by LoginValidator
 *           from a DB result that could itself have been injected] +
 *           request.getParameter("info") [direct user-controlled input]
 *   SINK (fixed): PreparedStatement with bound parameters — no longer a
 *           string-concatenated UPDATE statement.
 */
public class ChangeInfoSqlInjectionTest extends TestCase {

    /** Relative path to the JSP file from the Maven project root. */
    private static final String JSP_RELATIVE_PATH =
            "src/main/webapp/vulnerability/csrf/change-info.jsp";

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
     * Statement is the class used with unsafe string concatenation queries
     * and must be replaced by PreparedStatement.
     */
    public void testStatementImportRemoved() {
        assertFalse(
                "change-info.jsp must not import java.sql.Statement; "
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
                "change-info.jsp must import java.sql.PreparedStatement "
                + "to use parameterized queries.",
                jspContent.contains("PreparedStatement"));
    }

    /**
     * Verify that the SQL UPDATE query uses '?' placeholders for both the
     * 'about' column value and the 'id' condition instead of directly
     * embedding user-controlled values into the query string.
     *
     * Safe pattern:   prepareStatement("UPDATE users SET about=? WHERE id=?")
     * Unsafe pattern: "Update users set about='" + info + "' where id=" + id
     */
    public void testSqlQueryUsesParameterPlaceholders() {
        assertTrue(
                "The SQL UPDATE query in change-info.jsp must use '?' bind parameters "
                + "instead of embedding 'info' or 'id' directly in the query string.",
                jspContent.contains("about=?") && jspContent.contains("id=?"));
    }

    /**
     * Verify that the 'info' parameter is bound via setString() rather than
     * concatenated into the query string.
     */
    public void testInfoBoundWithSetString() {
        assertTrue(
                "change-info.jsp must bind 'info' using stmt.setString(1, info) "
                + "on the PreparedStatement.",
                jspContent.contains("setString(1, info)"));
    }

    /**
     * Verify that the 'id' value is bound via a setter rather than
     * concatenated into the WHERE clause.
     */
    public void testIdBoundWithSetter() {
        // The id may be bound as setString or setInt/setLong depending on the column type.
        assertTrue(
                "change-info.jsp must bind 'id' using a PreparedStatement setter "
                + "(setString(2, id), setInt(2, ...), or setLong(2, ...)).",
                jspContent.contains("setString(2, id)")
                || jspContent.contains("setInt(2,")
                || jspContent.contains("setLong(2,"));
    }

    /**
     * Verify that executeUpdate() is called with no SQL string argument
     * (PreparedStatement form), not the Statement form that takes a SQL string.
     */
    public void testExecuteUpdateCalledWithoutArgument() {
        assertTrue(
                "change-info.jsp must call executeUpdate() with no arguments "
                + "(PreparedStatement form) rather than passing the SQL string directly.",
                jspContent.contains("stmt.executeUpdate()"));
    }

    /**
     * Verify that the 'info' parameter is NOT directly concatenated into any
     * SQL string in the file. This catches the original vulnerable pattern:
     *   "Update users set about='" + info + "' where id=" + id
     */
    public void testNoDirectInfoConcatenationInSql() {
        // Matches patterns like: "...about='" + info   or   "..." + info + "..."
        Pattern unsafeInfoPattern = Pattern.compile(
                "(executeUpdate|executeQuery)\\s*\\(\\s*\"[^\"]*\"\\s*\\+\\s*info");
        assertFalse(
                "change-info.jsp must not concatenate 'info' directly into an "
                + "executeUpdate() or executeQuery() call. "
                + "Use PreparedStatement with a bind parameter instead.",
                unsafeInfoPattern.matcher(jspContent).find());
    }

    /**
     * Verify that the 'id' value is NOT directly concatenated into any
     * SQL string in the file. This catches the second half of the original
     * vulnerable pattern: "... where id=" + id
     */
    public void testNoDirectIdConcatenationInSql() {
        Pattern unsafeIdPattern = Pattern.compile(
                "(executeUpdate|executeQuery)\\s*\\(\\s*\"[^\"]*\"\\s*\\+\\s*id");
        assertFalse(
                "change-info.jsp must not concatenate 'id' directly into an "
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
            "about='\"+",
            "about='\" +",
            "\"+ info",
            "\" + info",
            "id=\"+id",
            "id=\" + id"
        };
        for (String token : dangerousTokens) {
            assertFalse(
                    "change-info.jsp must not contain the SQL concatenation token: [" + token + "]",
                    jspContent.contains(token));
        }
    }

    /**
     * Verify that con.prepareStatement() is called (not con.createStatement()),
     * confirming the switch from the vulnerable Statement API to PreparedStatement.
     */
    public void testPrepareStatementUsed() {
        assertTrue(
                "change-info.jsp must call con.prepareStatement(...) "
                + "instead of con.createStatement().",
                jspContent.contains("con.prepareStatement("));

        assertFalse(
                "change-info.jsp must not call con.createStatement() "
                + "since that API does not support bind parameters.",
                jspContent.contains("con.createStatement()"));
    }
}
