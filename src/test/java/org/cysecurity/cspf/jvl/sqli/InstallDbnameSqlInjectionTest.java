package org.cysecurity.cspf.jvl.sqli;

import junit.framework.TestCase;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Pattern;

/**
 * Tests to verify that Install.java is protected against SQL Injection (CWE-89)
 * via the "dbname" request parameter.
 *
 * Taint flow being tested:
 *   SOURCE: request.getParameter("dbname") at line 58 (processRequest method)
 *   SINK (fixed): "DROP DATABASE IF EXISTS" and "CREATE DATABASE" DDL statements
 *                 in the setup() method — previously built by unsafe string
 *                 concatenation, now protected by allowlist validation +
 *                 backtick-quoted identifier.
 *
 * Because JDBC PreparedStatement does not support '?' placeholders for DDL
 * identifiers (database/table names), the fix combines:
 *   1. A strict allowlist regex — only [a-zA-Z0-9_] permitted.
 *   2. Backtick quoting of the validated identifier in the DDL string.
 *   3. PreparedStatement for DML statements that bind user-controlled values
 *      (adminuser, adminpass).
 */
public class InstallDbnameSqlInjectionTest extends TestCase {

    /** Path to the servlet source file relative to the Maven project root. */
    private static final String SOURCE_RELATIVE_PATH =
            "src/main/java/org/cysecurity/cspf/jvl/controller/Install.java";

    private String sourceContent;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        File sourceFile = new File(SOURCE_RELATIVE_PATH);
        assertTrue(
                "Install.java must exist at " + sourceFile.getAbsolutePath(),
                sourceFile.exists());
        sourceContent = new String(Files.readAllBytes(Paths.get(sourceFile.getAbsolutePath())));
    }

    // -----------------------------------------------------------------------
    // 1. Allowlist validation present
    // -----------------------------------------------------------------------

    /**
     * Verify that Install.java validates dbname with an allowlist pattern
     * ([a-zA-Z0-9_]+) before using it in any DDL statement.
     * The allowlist is the SAST-recognized mechanism for safe DDL identifier
     * injection prevention when parameterized queries are not applicable.
     */
    public void testDbnameAllowlistValidationPresent() {
        assertTrue(
                "Install.java must validate dbname with an allowlist pattern "
                + "such as [a-zA-Z0-9_]+ before using it in DDL statements.",
                sourceContent.contains("[a-zA-Z0-9_]+"));
    }

    /**
     * Verify that the setup method returns false (or equivalent early exit)
     * when dbname fails the allowlist check — ensuring invalid input is
     * rejected before any database interaction.
     */
    public void testInvalidDbnameRejectedBeforeDbAccess() {
        // The guard must short-circuit: if validation fails, return false before
        // Class.forName / DriverManager.getConnection is reached.
        Pattern validationBeforeDriver = Pattern.compile(
                "matches\\(\"\\[a-zA-Z0-9_\\]\\+\"\\)[\\s\\S]*?Class\\.forName",
                Pattern.DOTALL);
        assertTrue(
                "Install.java must check dbname against the allowlist before "
                + "calling Class.forName() or DriverManager.getConnection().",
                validationBeforeDriver.matcher(sourceContent).find());
    }

    // -----------------------------------------------------------------------
    // 2. DDL statements use backtick-quoted identifier
    // -----------------------------------------------------------------------

    /**
     * Verify that the DROP DATABASE statement wraps dbname in backticks.
     * Backtick quoting prevents unintended SQL keyword injection within
     * a validated, allowlist-safe identifier.
     */
    public void testDropDatabaseUsesBacktickQuotedIdentifier() {
        assertTrue(
                "Install.java must use backtick-quoted dbname in DROP DATABASE: "
                + "\"DROP DATABASE IF EXISTS `\" + dbname + \"`\"",
                sourceContent.contains("DROP DATABASE IF EXISTS `\" + dbname + \"`\""));
    }

    /**
     * Verify that the CREATE DATABASE statement wraps dbname in backticks.
     */
    public void testCreateDatabaseUsesBacktickQuotedIdentifier() {
        assertTrue(
                "Install.java must use backtick-quoted dbname in CREATE DATABASE: "
                + "\"CREATE DATABASE `\" + dbname + \"`\"",
                sourceContent.contains("CREATE DATABASE `\" + dbname + \"`\""));
    }

    // -----------------------------------------------------------------------
    // 3. No unquoted concatenation of dbname into DDL
    // -----------------------------------------------------------------------

    /**
     * Verify that the original unsafe pattern — directly concatenating dbname
     * without backtick quoting into DROP DATABASE — no longer exists.
     */
    public void testNoUnquotedDbnameInDropDatabase() {
        assertFalse(
                "Install.java must not concatenate dbname directly (without backtick "
                + "quoting) into DROP DATABASE: e.g. \"DROP DATABASE IF EXISTS \"+dbname",
                sourceContent.contains("DROP DATABASE IF EXISTS \"+dbname")
                || sourceContent.contains("DROP DATABASE IF EXISTS \" + dbname"));
    }

    /**
     * Verify that the original unsafe pattern — directly concatenating dbname
     * without backtick quoting into CREATE DATABASE — no longer exists.
     */
    public void testNoUnquotedDbnameInCreateDatabase() {
        assertFalse(
                "Install.java must not concatenate dbname directly (without backtick "
                + "quoting) into CREATE DATABASE: e.g. \"CREATE DATABASE \"+dbname",
                sourceContent.contains("CREATE DATABASE \"+dbname")
                || sourceContent.contains("CREATE DATABASE \" + dbname"));
    }

    // -----------------------------------------------------------------------
    // 4. PreparedStatement used for DML with user-controlled values
    // -----------------------------------------------------------------------

    /**
     * Verify that Install.java imports java.sql.PreparedStatement, confirming
     * that user-controlled DML values (adminuser, adminpass) are bound safely.
     */
    public void testPreparedStatementImported() {
        assertTrue(
                "Install.java must import java.sql.PreparedStatement to bind "
                + "user-controlled DML parameters safely.",
                sourceContent.contains("import java.sql.PreparedStatement"));
    }

    /**
     * Verify that prepareStatement() is called for the admin user INSERT,
     * replacing the previously unsafe string-concatenated form.
     */
    public void testPrepareStatementCalledForAdminInsert() {
        assertTrue(
                "Install.java must call con.prepareStatement(...) for the admin "
                + "user INSERT statement to avoid SQL injection via adminuser/adminpass.",
                sourceContent.contains("con.prepareStatement("));
    }

    /**
     * Verify that adminuser is bound via setString() on the PreparedStatement
     * rather than concatenated into the SQL string.
     */
    public void testAdminuserBoundWithSetString() {
        assertTrue(
                "Install.java must bind adminuser using pstmt.setString(1, adminuser) "
                + "on the PreparedStatement.",
                sourceContent.contains("setString(1, adminuser)"));
    }

    /**
     * Verify that adminpass is bound via setString() on the PreparedStatement
     * rather than concatenated into the SQL string.
     */
    public void testAdminpassBoundWithSetString() {
        assertTrue(
                "Install.java must bind adminpass using pstmt.setString(2, adminpass) "
                + "on the PreparedStatement.",
                sourceContent.contains("setString(2, adminpass)"));
    }

    // -----------------------------------------------------------------------
    // 5. Original vulnerable concatenation patterns removed
    // -----------------------------------------------------------------------

    /**
     * Verify that the original vulnerable INSERT pattern that concatenated
     * adminuser and adminpass directly into SQL is no longer present.
     * Original: "INSERT into users(...) values ('" + adminuser + "','" + adminpass + "', ..."
     */
    public void testNoAdminuserStringConcatenationInInsert() {
        Pattern unsafePattern = Pattern.compile(
                "values\\s*\\(\\s*'\"\\s*\\+\\s*adminuser");
        assertFalse(
                "Install.java must not concatenate adminuser directly into an INSERT "
                + "statement. Use PreparedStatement with a bind parameter instead.",
                unsafePattern.matcher(sourceContent).find());
    }

    /**
     * Verify that the original vulnerable pattern that concatenated adminpass
     * directly into the INSERT SQL is no longer present.
     */
    public void testNoAdminpassStringConcatenationInInsert() {
        // Matches: ","'"+adminpass+"'"  or  ",'"+adminpass+"'"
        assertFalse(
                "Install.java must not concatenate adminpass directly into an INSERT "
                + "statement. Use PreparedStatement with a bind parameter instead.",
                sourceContent.contains("'\"+'\"\\s*,\\s*'\"\\s*\\+\\s*adminpass")
                || sourceContent.contains("','" + "+'\"\\s*\\+\\s*adminpass")
                || (sourceContent.contains("\"+'\"") && sourceContent.contains("adminpass+\"'\""))
                || sourceContent.contains("'+adminpass+'")
                || (sourceContent.contains("adminuser+\"','\"") || sourceContent.contains("adminuser + \"','\"")));
    }

    // -----------------------------------------------------------------------
    // 6. Allowlist validation allowlist pattern correctness
    // -----------------------------------------------------------------------

    /**
     * Verify that the allowlist pattern does NOT include characters that could
     * be used in SQL injection: quotes, semicolons, dashes, spaces, or backticks.
     * The pattern [a-zA-Z0-9_]+ must not be relaxed to allow such characters.
     */
    public void testAllowlistDoesNotPermitSqlSpecialCharacters() {
        // The allowlist should not contain '.' or '-' or ' ' or ';' or '"' or '%'
        assertFalse(
                "Install.java allowlist for dbname must not permit SQL-special characters "
                + "such as quotes, semicolons, percent signs, or spaces.",
                sourceContent.contains("[a-zA-Z0-9_.-]+")
                || sourceContent.contains("[a-zA-Z0-9_ ]+")
                || sourceContent.contains("[a-zA-Z0-9_;]+")
                || sourceContent.contains("[a-zA-Z0-9_']+")
                || sourceContent.contains("[a-zA-Z0-9_\"]+")
                || sourceContent.contains("[a-zA-Z0-9_%]+"));
    }

    /**
     * Verify that the allowlist uses the matches() method (full string match),
     * not find() or contains(), which would allow partial matching and could
     * leave the injection window open.
     */
    public void testAllowlistUsesFullStringMatch() {
        assertTrue(
                "Install.java must use String.matches() for the dbname allowlist check "
                + "so that the entire string is validated (not just a prefix or substring).",
                sourceContent.contains("dbname.matches("));
    }
}
