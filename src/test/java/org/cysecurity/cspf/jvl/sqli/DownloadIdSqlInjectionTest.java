package org.cysecurity.cspf.jvl.sqli;

import junit.framework.TestCase;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Pattern;

/**
 * Tests to verify that download_id.jsp is protected against SQL injection
 * by using a parameterized PreparedStatement rather than string concatenation.
 *
 * CWE-89: Improper Neutralization of Special Elements used in an SQL Command
 * The fix replaces Statement + string concatenation with PreparedStatement + bind parameters.
 */
public class DownloadIdSqlInjectionTest extends TestCase {

    /** Relative path to the vulnerable JSP from the project root. */
    private static final String JSP_RELATIVE_PATH =
            "src/main/webapp/vulnerability/sqli/download_id.jsp";

    private String jspContent;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        // Locate the JSP file relative to the working directory used by Maven (project root)
        File jspFile = new File(JSP_RELATIVE_PATH);
        assertTrue("JSP file must exist at " + jspFile.getAbsolutePath(), jspFile.exists());
        jspContent = new String(Files.readAllBytes(Paths.get(jspFile.getAbsolutePath())));
    }

    /**
     * Verify that the JSP no longer imports java.sql.Statement.
     * Statement is the class used with unsafe string concatenation queries.
     */
    public void testStatementImportRemoved() {
        assertFalse(
                "download_id.jsp must not import java.sql.Statement; "
                + "Statement allows raw SQL string concatenation which enables SQL injection.",
                jspContent.contains("import=\"java.sql.Statement\"")
                || jspContent.contains("import java.sql.Statement"));
    }

    /**
     * Verify that the JSP imports java.sql.PreparedStatement.
     * PreparedStatement is the JDBC API that supports parameterized queries.
     */
    public void testPreparedStatementImported() {
        assertTrue(
                "download_id.jsp must import java.sql.PreparedStatement "
                + "to use parameterized queries.",
                jspContent.contains("PreparedStatement"));
    }

    /**
     * Verify that the SQL query uses a '?' placeholder instead of
     * directly concatenating the 'fileid' parameter into the query string.
     *
     * The safe pattern is:  prepareStatement("... fileid=?")
     * The unsafe pattern is: "... fileid=" + fileid  (any form of concatenation)
     */
    public void testSqlQueryUsesParameterPlaceholder() {
        assertTrue(
                "The SQL query in download_id.jsp must use a '?' bind parameter "
                + "instead of embedding the fileid value directly in the query string.",
                jspContent.contains("fileid=?"));
    }

    /**
     * Verify that the file no longer concatenates 'fileid' directly into an
     * executeQuery() call. The unsafe pattern is:
     *   stmt.executeQuery("... fileid=" + fileid)
     */
    public void testNoDirectStringConcatenationInQuery() {
        // The vulnerable pattern concatenates fileid into the query argument of executeQuery
        Pattern unsafePattern = Pattern.compile(
                "executeQuery\\s*\\(\\s*\"[^\"]*\"\\s*\\+\\s*fileid");
        assertFalse(
                "download_id.jsp must not pass a concatenated fileid string to executeQuery(). "
                + "Use PreparedStatement with a bind parameter instead.",
                unsafePattern.matcher(jspContent).find());
    }

    /**
     * Verify that the parameterized query is executed via the no-argument
     * executeQuery() on PreparedStatement, not via the String-argument
     * executeQuery(String) on Statement.
     */
    public void testExecuteQueryCalledWithoutArgument() {
        // Safe form: stmt.executeQuery()  — no SQL string argument
        assertTrue(
                "download_id.jsp must call executeQuery() with no arguments "
                + "(PreparedStatement form) rather than passing the SQL string directly.",
                jspContent.contains("stmt.executeQuery()"));
    }

    /**
     * Verify that the bind parameter is set via setString (or a typed setter),
     * which is how PreparedStatement binds values safely.
     */
    public void testBindParameterSetOnStatement() {
        assertTrue(
                "download_id.jsp must use stmt.setString() (or equivalent setXxx()) "
                + "to bind the fileid value to the PreparedStatement placeholder.",
                jspContent.contains("stmt.setString(1, fileid)")
                || jspContent.contains("stmt.setInt(1,")
                || jspContent.contains("stmt.setLong(1,"));
    }

    /**
     * Regression: confirm that a classic SQL injection payload that would
     * have broken the original query is NOT embedded literally in any SQL
     * string within the JSP.  This guards against re-introducing an inline
     * payload by accident.
     */
    public void testNoSqlInjectionPayloadInQueryString() {
        // These are tokens that only appear when SQL is being constructed via concatenation
        String[] dangerousTokens = {
            "fileid=\" +",
            "fileid=\"+",
            "\" + fileid",
            "\"+fileid"
        };
        for (String token : dangerousTokens) {
            assertFalse(
                    "download_id.jsp must not contain the concatenation token: " + token,
                    jspContent.contains(token));
        }
    }
}
