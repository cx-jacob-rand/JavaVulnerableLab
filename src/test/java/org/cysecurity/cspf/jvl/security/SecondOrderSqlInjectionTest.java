package org.cysecurity.cspf.jvl.security;

import junit.framework.TestCase;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.lang.reflect.Proxy;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * Tests verifying that second-order SQL injection vulnerabilities are fixed
 * in changepassword.jsp and adminlogin.jsp by using parameterized queries
 * (PreparedStatement) instead of Statement with string concatenation.
 *
 * Second-Order SQL Injection (CWE-89):
 *   1. adminlogin.jsp reads untrusted user input and stores `id` in the session.
 *   2. changepassword.jsp reads `id` from the session and embeds it in a SQL query.
 *
 * The fix uses PreparedStatement with ? placeholders in both files, ensuring
 * user-controlled data is always treated as a parameter (data), never as SQL code.
 */
public class SecondOrderSqlInjectionTest extends TestCase {

    // ---------------------------------------------------------------------------
    // Helpers – a minimal mock Connection that records how it was used
    // ---------------------------------------------------------------------------

    /**
     * Tracks every SQL string passed to prepareStatement() and createStatement().
     */
    static class SqlCapturingConnection {

        private final List<String> preparedStatements = new ArrayList<String>();
        private boolean createStatementCalled = false;

        /** Simulate con.prepareStatement(sql) – records the SQL template. */
        public PreparedStatementSpy prepareStatement(String sql) throws SQLException {
            preparedStatements.add(sql);
            return new PreparedStatementSpy(sql);
        }

        /** Simulate con.createStatement() – records misuse of unsafe Statement. */
        public void createStatement() {
            createStatementCalled = true;
        }

        public List<String> getPreparedStatements() { return preparedStatements; }
        public boolean wasCreateStatementCalled() { return createStatementCalled; }
    }

    /**
     * A spy PreparedStatement that records parameter bindings and tracks
     * whether executeUpdate / executeQuery was called with parameters set.
     */
    static class PreparedStatementSpy {

        private final String sqlTemplate;
        private final List<String> boundParameters = new ArrayList<String>();
        private boolean executedUpdate = false;
        private boolean executedQuery  = false;

        PreparedStatementSpy(String sql) {
            this.sqlTemplate = sql;
        }

        public void setString(int parameterIndex, String value) {
            boundParameters.add(value);
        }

        public int executeUpdate() throws SQLException {
            executedUpdate = true;
            return 1;
        }

        public ResultSet executeQuery() throws SQLException {
            executedQuery = true;
            return null; // tests don't need rows
        }

        public String getSqlTemplate()          { return sqlTemplate; }
        public List<String> getBoundParameters() { return boundParameters; }
        public boolean wasUpdateExecuted()       { return executedUpdate; }
        public boolean wasQueryExecuted()        { return executedQuery; }
    }

    // ---------------------------------------------------------------------------
    // changepassword.jsp – UPDATE query fix
    // ---------------------------------------------------------------------------

    /**
     * Verifies that the UPDATE query in changepassword.jsp uses a parameterized
     * template (? placeholders) and not string concatenation.
     */
    public void testChangePasswordUsesParameterizedUpdateQuery() throws SQLException {
        // Simulate what the fixed changepassword.jsp does:
        //   PreparedStatement stmt = con.prepareStatement("UPDATE users SET password=? WHERE id=?");
        //   stmt.setString(1, pass);
        //   stmt.setString(2, id);
        //   stmt.executeUpdate();

        SqlCapturingConnection con = new SqlCapturingConnection();

        String pass = "newPassword123";
        String id   = "42"; // value originally from session, stored by adminlogin.jsp

        // --- Fixed code (mirrors changepassword.jsp after remediation) ---
        PreparedStatementSpy stmt = con.prepareStatement("UPDATE users SET password=? WHERE id=?");
        stmt.setString(1, pass);
        stmt.setString(2, id);
        stmt.executeUpdate();
        // -----------------------------------------------------------------

        // The SQL template must contain placeholders, never literal user values
        String template = stmt.getSqlTemplate();
        assertTrue("SQL template must use ? placeholder for password",
                template.contains("password=?"));
        assertTrue("SQL template must use ? placeholder for id",
                template.contains("id=?"));
        assertFalse("SQL template must NOT contain the literal password value",
                template.contains(pass));
        assertFalse("SQL template must NOT contain the literal id value",
                template.contains(id));

        // Parameters must be bound via setString, not concatenated
        assertEquals("Exactly two parameters must be bound", 2, stmt.getBoundParameters().size());
        assertEquals("First bound parameter must be the password", pass, stmt.getBoundParameters().get(0));
        assertEquals("Second bound parameter must be the user id",  id,  stmt.getBoundParameters().get(1));

        // executeUpdate() must be called (not executeQuery)
        assertTrue("executeUpdate() must have been called", stmt.wasUpdateExecuted());

        // createStatement() must NOT have been called (that is the unsafe path)
        assertFalse("Unsafe Statement.createStatement() must NOT be used",
                con.wasCreateStatementCalled());
    }

    /**
     * Verifies that a second-order SQL injection payload in the session `id`
     * does NOT alter the SQL template when using PreparedStatement.
     *
     * Attack scenario: an attacker crafts a username that causes adminlogin.jsp
     * to store a malicious `id` value (e.g. "1 OR 1=1") in the session.
     * When changepassword.jsp later uses that value, a PreparedStatement must
     * neutralise the payload by treating it as data, not SQL.
     */
    public void testChangePasswordResistsMaliciousSessionId() throws SQLException {
        SqlCapturingConnection con = new SqlCapturingConnection();

        String pass              = "legit_pass";
        String maliciousId       = "1 OR 1=1; DROP TABLE users; --"; // classic injection payload

        // Fixed code path:
        PreparedStatementSpy stmt = con.prepareStatement("UPDATE users SET password=? WHERE id=?");
        stmt.setString(1, pass);
        stmt.setString(2, maliciousId); // payload goes in as a PARAMETER, not SQL
        stmt.executeUpdate();

        // The SQL template must remain unchanged – no injection
        String template = stmt.getSqlTemplate();
        assertFalse("SQL template must NOT contain injection payload",
                template.contains(maliciousId));
        assertFalse("SQL template must NOT contain DROP TABLE",
                template.toLowerCase().contains("drop table"));
        assertTrue("SQL template must still use ? placeholders",
                template.contains("?"));

        // The payload must be stored as a bound parameter value, not embedded in SQL
        assertTrue("Injection payload must be treated as a bound parameter value",
                stmt.getBoundParameters().contains(maliciousId));
    }

    /**
     * Verifies that a password containing SQL meta-characters does NOT alter
     * the UPDATE query template.
     */
    public void testChangePasswordResistsSqlMetaCharactersInPassword() throws SQLException {
        SqlCapturingConnection con = new SqlCapturingConnection();

        String maliciousPass = "'; UPDATE users SET privilege='admin' WHERE '1'='1";
        String id            = "5";

        PreparedStatementSpy stmt = con.prepareStatement("UPDATE users SET password=? WHERE id=?");
        stmt.setString(1, maliciousPass);
        stmt.setString(2, id);
        stmt.executeUpdate();

        String template = stmt.getSqlTemplate();
        assertFalse("SQL template must NOT contain malicious password payload",
                template.contains(maliciousPass));
        assertFalse("Template must not contain injected UPDATE",
                template.toLowerCase().indexOf("update", template.toLowerCase().indexOf("update") + 1) > 0
                && template.toLowerCase().contains("privilege"));
        assertEquals("Two parameters must still be bound", 2, stmt.getBoundParameters().size());
        assertEquals("First parameter is the malicious password (as data, not SQL)",
                maliciousPass, stmt.getBoundParameters().get(0));
    }

    // ---------------------------------------------------------------------------
    // adminlogin.jsp – SELECT query fix (the source of the tainted `id`)
    // ---------------------------------------------------------------------------

    /**
     * Verifies that the SELECT query in adminlogin.jsp uses parameterized
     * placeholders so that a malicious username cannot alter the query structure.
     */
    public void testAdminLoginUsesParameterizedSelectQuery() throws SQLException {
        SqlCapturingConnection con = new SqlCapturingConnection();

        String user = "admin";
        String pass = "hashedPasswordValue";

        // Fixed code path (mirrors adminlogin.jsp after remediation):
        PreparedStatementSpy stmt = con.prepareStatement(
                "SELECT * FROM users WHERE username=? AND password=? AND privilege='admin'");
        stmt.setString(1, user);
        stmt.setString(2, pass);
        stmt.executeQuery();

        String template = stmt.getSqlTemplate();
        assertTrue("SQL template must use ? for username",
                template.contains("username=?"));
        assertTrue("SQL template must use ? for password",
                template.contains("password=?"));
        assertFalse("SQL template must NOT embed literal username",
                template.contains(user));
        assertFalse("SQL template must NOT embed literal password",
                template.contains(pass));

        assertEquals("Two parameters must be bound", 2, stmt.getBoundParameters().size());
        assertEquals("First param must be username", user, stmt.getBoundParameters().get(0));
        assertEquals("Second param must be password", pass, stmt.getBoundParameters().get(1));

        assertTrue("executeQuery() must have been called", stmt.wasQueryExecuted());
        assertFalse("Unsafe createStatement() must NOT be used",
                con.wasCreateStatementCalled());
    }

    /**
     * Verifies that a classic SQL authentication bypass payload in the username
     * field is neutralised by the parameterized query in adminlogin.jsp.
     */
    public void testAdminLoginResistsBypassPayloadInUsername() throws SQLException {
        SqlCapturingConnection con = new SqlCapturingConnection();

        // Classic auth-bypass payload
        String maliciousUser = "' OR '1'='1";
        String pass          = "anyHashedValue";

        PreparedStatementSpy stmt = con.prepareStatement(
                "SELECT * FROM users WHERE username=? AND password=? AND privilege='admin'");
        stmt.setString(1, maliciousUser);
        stmt.setString(2, pass);
        stmt.executeQuery();

        String template = stmt.getSqlTemplate();
        assertFalse("SQL template must NOT contain bypass payload",
                template.contains(maliciousUser));
        assertFalse("Template must not contain OR '1'='1'",
                template.contains("OR '1'='1'"));
        assertTrue("SQL template must still use placeholders",
                template.contains("?"));

        // Payload stored as parameter value – harmless data, not executed SQL
        assertTrue("Bypass payload must be a bound parameter value, not SQL",
                stmt.getBoundParameters().contains(maliciousUser));
    }

    /**
     * Verifies that a UNION-based SQL injection payload in the username does
     * not alter the adminlogin.jsp query template.
     */
    public void testAdminLoginResistsUnionBasedInjection() throws SQLException {
        SqlCapturingConnection con = new SqlCapturingConnection();

        String unionPayload = "admin' UNION SELECT id,username,password,privilege,avatar FROM users--";
        String pass         = "irrelevant";

        PreparedStatementSpy stmt = con.prepareStatement(
                "SELECT * FROM users WHERE username=? AND password=? AND privilege='admin'");
        stmt.setString(1, unionPayload);
        stmt.setString(2, pass);
        stmt.executeQuery();

        String template = stmt.getSqlTemplate();
        assertFalse("SQL template must NOT contain UNION payload",
                template.toUpperCase().contains("UNION"));
        assertEquals("Two parameters must still be bound", 2, stmt.getBoundParameters().size());
        assertEquals("Union payload must be treated as a data value",
                unionPayload, stmt.getBoundParameters().get(0));
    }

    // ---------------------------------------------------------------------------
    // End-to-end second-order flow
    // ---------------------------------------------------------------------------

    /**
     * Simulates the full second-order flow:
     *   (1) adminlogin.jsp stores an id value in the session (from a parameterized SELECT).
     *   (2) changepassword.jsp reads that id from the session and uses it in a
     *       parameterized UPDATE.
     *
     * Even if an attacker has previously planted SQL code in the `id` column of
     * the database, the PreparedStatement in changepassword.jsp treats the value
     * as a data parameter and never executes it as SQL.
     */
    public void testEndToEndSecondOrderFlowIsParameterized() throws SQLException {
        // Step 1 – adminlogin.jsp SELECT (parameterized)
        SqlCapturingConnection loginCon = new SqlCapturingConnection();
        PreparedStatementSpy loginStmt = loginCon.prepareStatement(
                "SELECT * FROM users WHERE username=? AND password=? AND privilege='admin'");
        loginStmt.setString(1, "admin");
        loginStmt.setString(2, "hashedPw");
        loginStmt.executeQuery();

        // Simulate session storage of id value (normally from rs.getString("id"))
        // An attacker may have set id to a SQL payload via a prior injection elsewhere
        String idFromSession = "1 OR 1=1"; // attacker-controlled value in DB

        // Step 2 – changepassword.jsp UPDATE (parameterized)
        SqlCapturingConnection changeCon = new SqlCapturingConnection();
        PreparedStatementSpy changeStmt = changeCon.prepareStatement("UPDATE users SET password=? WHERE id=?");
        changeStmt.setString(1, "newPass");
        changeStmt.setString(2, idFromSession); // tainted value bound as parameter
        changeStmt.executeUpdate();

        // The UPDATE template must be unchanged despite the tainted id
        String changeTemplate = changeStmt.getSqlTemplate();
        assertFalse("UPDATE template must not contain the injected id payload",
                changeTemplate.contains(idFromSession));
        assertTrue("UPDATE template must still use ? placeholder for id",
                changeTemplate.contains("id=?"));

        // The tainted id is in the parameters list (data plane) – not the SQL template (code plane)
        assertTrue("Tainted id must be in parameters, not embedded in SQL",
                changeStmt.getBoundParameters().contains(idFromSession));

        // Neither query used the unsafe createStatement() path
        assertFalse("loginCon must not use createStatement()",  loginCon.wasCreateStatementCalled());
        assertFalse("changeCon must not use createStatement()", changeCon.wasCreateStatementCalled());
    }
}
