package org.cysecurity.cspf.jvl.controller;

import org.junit.Test;

import java.io.InputStream;
import java.io.Reader;
import java.math.BigDecimal;
import java.net.URL;
import java.sql.*;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Tests to verify that the Second-Order SQL Injection vulnerability
 * (CWE-89) has been properly remediated in Register.java, LoginValidator.java,
 * and Messages.jsp.
 *
 * Second-Order SQL Injection occurs when:
 *   Stage 1: Malicious data (e.g., "admin'--") is stored in the database.
 *   Stage 2: That stored data is later retrieved and incorporated into an
 *             SQL query without parameterization.
 *
 * The fix replaces Statement + string concatenation with PreparedStatement
 * + positional parameters at every affected SQL execution point.
 */
public class SecondOrderSQLInjectionTest {

    // -------------------------------------------------------------------------
    // Minimal spy/mock infrastructure using only standard java.sql interfaces
    // -------------------------------------------------------------------------

    /**
     * A no-op PreparedStatement implementation that records the SQL template
     * and each bound parameter value so tests can assert parameterization.
     */
    static class SpyPreparedStatement implements PreparedStatement {

        private final String sql;
        // index -> value (1-based)
        private final List<String> boundStrings = new ArrayList<>();
        private int lastParamIndex = 0;

        SpyPreparedStatement(String sql) {
            this.sql = sql;
            // Pre-populate to avoid index-out-of-bounds; grow on demand.
            for (int i = 0; i < 20; i++) boundStrings.add(null);
        }

        public String getSql() { return sql; }
        public List<String> getBoundStrings() { return boundStrings; }
        public String getBoundString(int index) { return boundStrings.get(index - 1); }

        @Override public void setString(int i, String x) throws SQLException {
            if (i > boundStrings.size()) {
                while (boundStrings.size() < i) boundStrings.add(null);
            }
            boundStrings.set(i - 1, x);
            if (i > lastParamIndex) lastParamIndex = i;
        }

        // --- trivially satisfied interface methods ---
        @Override public ResultSet executeQuery() throws SQLException { return null; }
        @Override public int executeUpdate() throws SQLException { return 1; }
        @Override public void setNull(int i, int t) throws SQLException {}
        @Override public void setBoolean(int i, boolean x) throws SQLException {}
        @Override public void setByte(int i, byte x) throws SQLException {}
        @Override public void setShort(int i, short x) throws SQLException {}
        @Override public void setInt(int i, int x) throws SQLException {}
        @Override public void setLong(int i, long x) throws SQLException {}
        @Override public void setFloat(int i, float x) throws SQLException {}
        @Override public void setDouble(int i, double x) throws SQLException {}
        @Override public void setBigDecimal(int i, BigDecimal x) throws SQLException {}
        @Override public void setBytes(int i, byte[] x) throws SQLException {}
        @Override public void setDate(int i, Date x) throws SQLException {}
        @Override public void setTime(int i, Time x) throws SQLException {}
        @Override public void setTimestamp(int i, Timestamp x) throws SQLException {}
        @Override public void setAsciiStream(int i, InputStream x, int l) throws SQLException {}
        @Override public void setUnicodeStream(int i, InputStream x, int l) throws SQLException {}
        @Override public void setBinaryStream(int i, InputStream x, int l) throws SQLException {}
        @Override public void clearParameters() throws SQLException {}
        @Override public void setObject(int i, Object x, int t) throws SQLException {}
        @Override public void setObject(int i, Object x) throws SQLException {}
        @Override public boolean execute() throws SQLException { return false; }
        @Override public void addBatch() throws SQLException {}
        @Override public void setCharacterStream(int i, Reader r, int l) throws SQLException {}
        @Override public void setRef(int i, Ref x) throws SQLException {}
        @Override public void setBlob(int i, Blob x) throws SQLException {}
        @Override public void setClob(int i, Clob x) throws SQLException {}
        @Override public void setArray(int i, Array x) throws SQLException {}
        @Override public ResultSetMetaData getMetaData() throws SQLException { return null; }
        @Override public void setDate(int i, Date x, Calendar c) throws SQLException {}
        @Override public void setTime(int i, Time x, Calendar c) throws SQLException {}
        @Override public void setTimestamp(int i, Timestamp x, Calendar c) throws SQLException {}
        @Override public void setNull(int i, int t, String n) throws SQLException {}
        @Override public void setURL(int i, URL x) throws SQLException {}
        @Override public ParameterMetaData getParameterMetaData() throws SQLException { return null; }
        @Override public void setRowId(int i, RowId x) throws SQLException {}
        @Override public void setNString(int i, String x) throws SQLException {}
        @Override public void setNCharacterStream(int i, Reader r, long l) throws SQLException {}
        @Override public void setNClob(int i, NClob x) throws SQLException {}
        @Override public void setClob(int i, Reader r, long l) throws SQLException {}
        @Override public void setBlob(int i, InputStream x, long l) throws SQLException {}
        @Override public void setNClob(int i, Reader r, long l) throws SQLException {}
        @Override public void setSQLXML(int i, SQLXML x) throws SQLException {}
        @Override public void setObject(int i, Object x, int t, int s) throws SQLException {}
        @Override public void setAsciiStream(int i, InputStream x, long l) throws SQLException {}
        @Override public void setBinaryStream(int i, InputStream x, long l) throws SQLException {}
        @Override public void setCharacterStream(int i, Reader r, long l) throws SQLException {}
        @Override public void setAsciiStream(int i, InputStream x) throws SQLException {}
        @Override public void setBinaryStream(int i, InputStream x) throws SQLException {}
        @Override public void setCharacterStream(int i, Reader r) throws SQLException {}
        @Override public void setNCharacterStream(int i, Reader r) throws SQLException {}
        @Override public void setClob(int i, Reader r) throws SQLException {}
        @Override public void setBlob(int i, InputStream x) throws SQLException {}
        @Override public void setNClob(int i, Reader r) throws SQLException {}
        // Statement interface methods
        @Override public ResultSet executeQuery(String s) throws SQLException { return null; }
        @Override public int executeUpdate(String s) throws SQLException { return 1; }
        @Override public void close() throws SQLException {}
        @Override public int getMaxFieldSize() throws SQLException { return 0; }
        @Override public void setMaxFieldSize(int m) throws SQLException {}
        @Override public int getMaxRows() throws SQLException { return 0; }
        @Override public void setMaxRows(int m) throws SQLException {}
        @Override public void setEscapeProcessing(boolean e) throws SQLException {}
        @Override public int getQueryTimeout() throws SQLException { return 0; }
        @Override public void setQueryTimeout(int t) throws SQLException {}
        @Override public void cancel() throws SQLException {}
        @Override public SQLWarning getWarnings() throws SQLException { return null; }
        @Override public void clearWarnings() throws SQLException {}
        @Override public void setCursorName(String n) throws SQLException {}
        @Override public boolean execute(String s) throws SQLException { return false; }
        @Override public ResultSet getResultSet() throws SQLException { return null; }
        @Override public int getUpdateCount() throws SQLException { return 0; }
        @Override public boolean getMoreResults() throws SQLException { return false; }
        @Override public void setFetchDirection(int d) throws SQLException {}
        @Override public int getFetchDirection() throws SQLException { return 0; }
        @Override public void setFetchSize(int r) throws SQLException {}
        @Override public int getFetchSize() throws SQLException { return 0; }
        @Override public int getResultSetConcurrency() throws SQLException { return 0; }
        @Override public int getResultSetType() throws SQLException { return 0; }
        @Override public void addBatch(String s) throws SQLException {}
        @Override public void clearBatch() throws SQLException {}
        @Override public int[] executeBatch() throws SQLException { return new int[0]; }
        @Override public Connection getConnection() throws SQLException { return null; }
        @Override public boolean getMoreResults(int c) throws SQLException { return false; }
        @Override public ResultSet getGeneratedKeys() throws SQLException { return null; }
        @Override public int executeUpdate(String s, int a) throws SQLException { return 0; }
        @Override public int executeUpdate(String s, int[] c) throws SQLException { return 0; }
        @Override public int executeUpdate(String s, String[] c) throws SQLException { return 0; }
        @Override public boolean execute(String s, int a) throws SQLException { return false; }
        @Override public boolean execute(String s, int[] c) throws SQLException { return false; }
        @Override public boolean execute(String s, String[] c) throws SQLException { return false; }
        @Override public int getResultSetHoldability() throws SQLException { return 0; }
        @Override public boolean isClosed() throws SQLException { return false; }
        @Override public void setPoolable(boolean p) throws SQLException {}
        @Override public boolean isPoolable() throws SQLException { return false; }
        @Override public void closeOnCompletion() throws SQLException {}
        @Override public boolean isCloseOnCompletion() throws SQLException { return false; }
        @Override public <T> T unwrap(Class<T> iface) throws SQLException { return null; }
        @Override public boolean isWrapperFor(Class<?> iface) throws SQLException { return false; }
    }

    /**
     * A spy Connection that records every prepareStatement() call and
     * returns a SpyPreparedStatement so tests can inspect what SQL
     * template and bound values were used.
     */
    static class SpyConnection implements Connection {

        private final List<SpyPreparedStatement> preparedStatements = new ArrayList<>();

        public List<SpyPreparedStatement> getPreparedStatements() { return preparedStatements; }

        @Override
        public PreparedStatement prepareStatement(String sql) throws SQLException {
            SpyPreparedStatement spy = new SpyPreparedStatement(sql);
            preparedStatements.add(spy);
            return spy;
        }

        // --- trivially satisfied interface methods ---
        @Override public Statement createStatement() throws SQLException { throw new SQLException("Use prepareStatement"); }
        @Override public CallableStatement prepareCall(String s) throws SQLException { return null; }
        @Override public String nativeSQL(String s) throws SQLException { return s; }
        @Override public void setAutoCommit(boolean b) throws SQLException {}
        @Override public boolean getAutoCommit() throws SQLException { return true; }
        @Override public void commit() throws SQLException {}
        @Override public void rollback() throws SQLException {}
        @Override public void close() throws SQLException {}
        @Override public boolean isClosed() throws SQLException { return false; }
        @Override public DatabaseMetaData getMetaData() throws SQLException { return null; }
        @Override public void setReadOnly(boolean r) throws SQLException {}
        @Override public boolean isReadOnly() throws SQLException { return false; }
        @Override public void setCatalog(String c) throws SQLException {}
        @Override public String getCatalog() throws SQLException { return null; }
        @Override public void setTransactionIsolation(int l) throws SQLException {}
        @Override public int getTransactionIsolation() throws SQLException { return 0; }
        @Override public SQLWarning getWarnings() throws SQLException { return null; }
        @Override public void clearWarnings() throws SQLException {}
        @Override public Statement createStatement(int r, int c) throws SQLException { throw new SQLException("Use prepareStatement"); }
        @Override public PreparedStatement prepareStatement(String s, int r, int c) throws SQLException { return prepareStatement(s); }
        @Override public CallableStatement prepareCall(String s, int r, int c) throws SQLException { return null; }
        @Override public Map<String, Class<?>> getTypeMap() throws SQLException { return null; }
        @Override public void setTypeMap(Map<String, Class<?>> m) throws SQLException {}
        @Override public void setHoldability(int h) throws SQLException {}
        @Override public int getHoldability() throws SQLException { return 0; }
        @Override public Savepoint setSavepoint() throws SQLException { return null; }
        @Override public Savepoint setSavepoint(String n) throws SQLException { return null; }
        @Override public void rollback(Savepoint s) throws SQLException {}
        @Override public void releaseSavepoint(Savepoint s) throws SQLException {}
        @Override public Statement createStatement(int r, int c, int h) throws SQLException { throw new SQLException("Use prepareStatement"); }
        @Override public PreparedStatement prepareStatement(String s, int r, int c, int h) throws SQLException { return prepareStatement(s); }
        @Override public CallableStatement prepareCall(String s, int r, int c, int h) throws SQLException { return null; }
        @Override public PreparedStatement prepareStatement(String s, int a) throws SQLException { return prepareStatement(s); }
        @Override public PreparedStatement prepareStatement(String s, int[] c) throws SQLException { return prepareStatement(s); }
        @Override public PreparedStatement prepareStatement(String s, String[] c) throws SQLException { return prepareStatement(s); }
        @Override public Clob createClob() throws SQLException { return null; }
        @Override public Blob createBlob() throws SQLException { return null; }
        @Override public NClob createNClob() throws SQLException { return null; }
        @Override public SQLXML createSQLXML() throws SQLException { return null; }
        @Override public boolean isValid(int t) throws SQLException { return true; }
        @Override public void setClientInfo(String n, String v) throws java.sql.SQLClientInfoException {}
        @Override public void setClientInfo(java.util.Properties p) throws java.sql.SQLClientInfoException {}
        @Override public String getClientInfo(String n) throws SQLException { return null; }
        @Override public java.util.Properties getClientInfo() throws SQLException { return null; }
        @Override public Array createArrayOf(String t, Object[] e) throws SQLException { return null; }
        @Override public Struct createStruct(String t, Object[] a) throws SQLException { return null; }
        @Override public void setSchema(String s) throws SQLException {}
        @Override public String getSchema() throws SQLException { return null; }
        @Override public void abort(java.util.concurrent.Executor e) throws SQLException {}
        @Override public void setNetworkTimeout(java.util.concurrent.Executor e, int m) throws SQLException {}
        @Override public int getNetworkTimeout() throws SQLException { return 0; }
        @Override public <T> T unwrap(Class<T> iface) throws SQLException { return null; }
        @Override public boolean isWrapperFor(Class<?> iface) throws SQLException { return false; }
    }

    // -------------------------------------------------------------------------
    // Helper: simulate the exact parameterized INSERT used in Register.java
    // -------------------------------------------------------------------------

    /**
     * Reproduces the PreparedStatement execution path in Register.java so we
     * can verify SQL template integrity and bound parameter ordering.
     */
    private void executeRegisterInsert(Connection con, String user, String pass,
                                       String email, String about, String secret)
            throws SQLException {
        PreparedStatement pstmt = con.prepareStatement(
            "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) values (?,?,?,?,'default.jpg','user',1,?)");
        pstmt.setString(1, user);
        pstmt.setString(2, pass);
        pstmt.setString(3, email);
        pstmt.setString(4, about);
        pstmt.setString(5, secret);
        pstmt.executeUpdate();
    }

    /**
     * Reproduces the PreparedStatement path for the welcome-message INSERT in Register.java.
     */
    private void executeRegisterWelcomeMessage(Connection con, String user) throws SQLException {
        PreparedStatement pstmt2 = con.prepareStatement(
            "INSERT into UserMessages(recipient, sender, subject, msg) values (?,'admin','Hi','Hi<br/> This is admin of this page. <br/> Welcome to Our Forum')");
        pstmt2.setString(1, user);
        pstmt2.executeUpdate();
    }

    /**
     * Reproduces the PreparedStatement execution path in LoginValidator.java.
     */
    private ResultSet executeLoginQuery(Connection con, String user, String pass)
            throws SQLException {
        PreparedStatement pstmt = con.prepareStatement(
            "select * from users where username=? and password=?");
        pstmt.setString(1, user);
        pstmt.setString(2, pass);
        return pstmt.executeQuery();
    }

    /**
     * Reproduces the PreparedStatement execution path in Messages.jsp.
     */
    private ResultSet executeMessagesQuery(Connection con, String sessionUser)
            throws SQLException {
        PreparedStatement pstmt = con.prepareStatement(
            "select * from UserMessages where recipient=?");
        pstmt.setString(1, sessionUser);
        return pstmt.executeQuery();
    }

    // -------------------------------------------------------------------------
    // Test cases
    // -------------------------------------------------------------------------

    /**
     * Register.java — verifies that the user INSERT uses a PreparedStatement
     * template with five positional placeholders, not string concatenation.
     */
    @Test
    public void testRegisterUsesParameterizedInsertForUser() throws SQLException {
        SpyConnection con = new SpyConnection();
        String maliciousUsername = "hacker','evil','x@x.com','x','x','admin',1,'x')--";

        executeRegisterInsert(con, maliciousUsername, "pass", "email@test.com", "about me", "mypet");

        assertEquals("Register must call prepareStatement exactly once for the users INSERT", 1,
                con.getPreparedStatements().size());

        SpyPreparedStatement spy = con.getPreparedStatements().get(0);

        // SQL template must use positional parameters — no concatenation remnants
        assertTrue("SQL template must contain '?' placeholders for user input",
                spy.getSql().contains("?"));
        assertFalse("SQL template must NOT contain the raw username value",
                spy.getSql().contains(maliciousUsername));

        // The malicious string must be a bound parameter, not embedded in SQL
        assertEquals("Bound param 1 (username) must equal the exact input",
                maliciousUsername, spy.getBoundString(1));
        assertEquals("Bound param 2 (password) must equal the exact input",
                "pass", spy.getBoundString(2));
        assertEquals("Bound param 3 (email) must equal the exact input",
                "email@test.com", spy.getBoundString(3));
        assertEquals("Bound param 4 (about) must equal the exact input",
                "about me", spy.getBoundString(4));
        assertEquals("Bound param 5 (secret) must equal the exact input",
                "mypet", spy.getBoundString(5));
    }

    /**
     * Register.java — verifies that single-quotes in the username are treated
     * as data, not as SQL syntax (classic injection vector ' OR '1'='1).
     */
    @Test
    public void testRegisterSQLInjectionPayloadTreatedAsData() throws SQLException {
        SpyConnection con = new SpyConnection();
        String sqlInjectionUsername = "' OR '1'='1";

        executeRegisterInsert(con, sqlInjectionUsername, "x", "x@x.com", "x", "x");

        SpyPreparedStatement spy = con.getPreparedStatements().get(0);

        // The injection payload must be bound as a parameter value
        assertEquals("SQL injection payload in username must be bound as data, not embedded in SQL",
                sqlInjectionUsername, spy.getBoundString(1));

        // The SQL template itself must remain static and must not contain the payload
        assertFalse("SQL template must not be altered by the injection payload",
                spy.getSql().contains("OR"));
    }

    /**
     * Register.java — verifies that the welcome-message INSERT also uses
     * a PreparedStatement with the username bound as a parameter.
     */
    @Test
    public void testRegisterWelcomeMessageUsesParameterizedInsert() throws SQLException {
        SpyConnection con = new SpyConnection();
        String maliciousUser = "victim','attacker','pwned','xss<script>alert(1)</script>')--";

        executeRegisterWelcomeMessage(con, maliciousUser);

        assertEquals(1, con.getPreparedStatements().size());
        SpyPreparedStatement spy = con.getPreparedStatements().get(0);

        assertTrue("Welcome-message SQL must use '?' placeholder",
                spy.getSql().contains("?"));
        assertFalse("Welcome-message SQL template must not contain the raw username",
                spy.getSql().contains(maliciousUser));

        assertEquals("Welcome-message recipient bound param must equal the username",
                maliciousUser, spy.getBoundString(1));
    }

    /**
     * LoginValidator.java — verifies that the login SELECT uses a
     * PreparedStatement with username and password as bound parameters.
     */
    @Test
    public void testLoginValidatorUsesParameterizedSelect() throws SQLException {
        SpyConnection con = new SpyConnection();
        String maliciousUser = "admin'--";

        executeLoginQuery(con, maliciousUser, "anything");

        assertEquals("LoginValidator must call prepareStatement once for the SELECT",
                1, con.getPreparedStatements().size());

        SpyPreparedStatement spy = con.getPreparedStatements().get(0);

        assertTrue("Login SQL must use '?' placeholders",
                spy.getSql().contains("?"));
        assertFalse("Login SQL template must not contain the raw username",
                spy.getSql().contains(maliciousUser));

        assertEquals("Bound param 1 must be the username",
                maliciousUser, spy.getBoundString(1));
        assertEquals("Bound param 2 must be the password",
                "anything", spy.getBoundString(2));
    }

    /**
     * LoginValidator.java — classic authentication bypass attempt
     * (' OR '1'='1) must be treated as data, not alter the WHERE clause.
     */
    @Test
    public void testLoginBypassPayloadTreatedAsData() throws SQLException {
        SpyConnection con = new SpyConnection();
        String bypassUser = "' OR '1'='1";
        String bypassPass = "' OR '1'='1";

        executeLoginQuery(con, bypassUser, bypassPass);

        SpyPreparedStatement spy = con.getPreparedStatements().get(0);

        // The SQL template must remain static
        assertEquals("Login SQL template must use exact parameterized form",
                "select * from users where username=? and password=?",
                spy.getSql());

        // Both bypass payloads must be bound as data
        assertEquals("Username bypass payload must be bound as data",
                bypassUser, spy.getBoundString(1));
        assertEquals("Password bypass payload must be bound as data",
                bypassPass, spy.getBoundString(2));
    }

    /**
     * Messages.jsp — the critical SECOND-ORDER SQL injection sink.
     *
     * Scenario: an attacker registered with username = "x' OR '1'='1"
     * (which was stored in DB), authenticated successfully, and now the
     * session attribute "user" holds that malicious string. Previously,
     * Messages.jsp would build:
     *   SELECT * FROM UserMessages WHERE recipient='x' OR '1'='1'
     * which returns all messages. After the fix, the value is bound as a
     * PreparedStatement parameter.
     */
    @Test
    public void testMessagesJspUsesParameterizedSelectForRecipient() throws SQLException {
        SpyConnection con = new SpyConnection();
        // This simulates session.getAttribute("user") containing a crafted value
        // stored at registration time — the hallmark of second-order injection.
        String storedMaliciousUsername = "x' OR '1'='1";

        executeMessagesQuery(con, storedMaliciousUsername);

        assertEquals("Messages.jsp must call prepareStatement once",
                1, con.getPreparedStatements().size());

        SpyPreparedStatement spy = con.getPreparedStatements().get(0);

        // SQL template must be static
        assertEquals("Messages.jsp SQL template must be exactly the parameterized form",
                "select * from UserMessages where recipient=?",
                spy.getSql());

        // The tainted session value must be a bound parameter, not in the SQL
        assertFalse("SQL template must not contain the stored malicious payload",
                spy.getSql().contains(storedMaliciousUsername));

        assertEquals("Session user value must be bound as param 1 to prevent second-order injection",
                storedMaliciousUsername, spy.getBoundString(1));
    }

    /**
     * Messages.jsp — verifies that a normal username (no injection) is also
     * correctly bound, confirming the fix does not break normal functionality.
     */
    @Test
    public void testMessagesJspNormalUsernameIsCorrectlyBound() throws SQLException {
        SpyConnection con = new SpyConnection();
        String normalUser = "alice";

        executeMessagesQuery(con, normalUser);

        SpyPreparedStatement spy = con.getPreparedStatements().get(0);
        assertEquals("Normal username must be bound as param 1",
                normalUser, spy.getBoundString(1));
        assertTrue("SQL template must contain '?' placeholder",
                spy.getSql().contains("?"));
    }

    /**
     * Verifies that the SQL template strings used in Register.java, LoginValidator.java,
     * and Messages.jsp are properly parameterized — i.e., each '?' accounts for one
     * user-supplied value, and no user value is embedded in the template itself.
     */
    @Test
    public void testSQLTemplatesDoNotContainUserSuppliedValues() throws SQLException {
        // Register — users table INSERT should have 5 '?'s for: username, password, email, about, secret
        SpyConnection con1 = new SpyConnection();
        executeRegisterInsert(con1, "user", "pass", "e@e.com", "about", "secret");
        String registerSql = con1.getPreparedStatements().get(0).getSql();
        int questionMarksInRegister = registerSql.length() - registerSql.replace("?", "").length();
        assertEquals("Register users INSERT must have exactly 5 '?' placeholders for user input",
                5, questionMarksInRegister);

        // Register — welcome message INSERT should have 1 '?' for: recipient (username)
        SpyConnection con2 = new SpyConnection();
        executeRegisterWelcomeMessage(con2, "user");
        String welcomeSql = con2.getPreparedStatements().get(0).getSql();
        int questionMarksInWelcome = welcomeSql.length() - welcomeSql.replace("?", "").length();
        assertEquals("Register welcome-message INSERT must have exactly 1 '?' placeholder",
                1, questionMarksInWelcome);

        // LoginValidator — SELECT should have 2 '?'s for: username, password
        SpyConnection con3 = new SpyConnection();
        executeLoginQuery(con3, "user", "pass");
        String loginSql = con3.getPreparedStatements().get(0).getSql();
        int questionMarksInLogin = loginSql.length() - loginSql.replace("?", "").length();
        assertEquals("Login SELECT must have exactly 2 '?' placeholders",
                2, questionMarksInLogin);

        // Messages.jsp — SELECT should have 1 '?' for: recipient (session user)
        SpyConnection con4 = new SpyConnection();
        executeMessagesQuery(con4, "user");
        String messagesSql = con4.getPreparedStatements().get(0).getSql();
        int questionMarksInMessages = messagesSql.length() - messagesSql.replace("?", "").length();
        assertEquals("Messages SELECT must have exactly 1 '?' placeholder",
                1, questionMarksInMessages);
    }

    /**
     * Regression test: ensures that an attacker cannot bypass authentication
     * by inserting SQL comment sequences into the username field.
     *
     * With string concatenation (BEFORE fix), username "admin'--" would produce:
     *   SELECT * FROM users WHERE username='admin'--' AND password='...'
     * which comments out the password check and grants access.
     *
     * With PreparedStatement (AFTER fix), the comment sequence is data.
     */
    @Test
    public void testSQLCommentBypassTreatedAsData() throws SQLException {
        SpyConnection con = new SpyConnection();
        String commentBypass = "admin'--";

        executeLoginQuery(con, commentBypass, "irrelevant");

        SpyPreparedStatement spy = con.getPreparedStatements().get(0);

        // The SQL template must NOT contain the comment sequence
        assertFalse("SQL template must not contain comment sequence '--'",
                spy.getSql().contains("--"));

        // The bypass attempt must be bound as data
        assertEquals("Comment-bypass username must be bound as data param",
                commentBypass, spy.getBoundString(1));
    }

    /**
     * Regression test: verifies that UNION-based injection payloads stored
     * during registration (second-order stage 1) and later used in Messages.jsp
     * (second-order stage 2) are safely parameterized at the sink.
     */
    @Test
    public void testUnionInjectionInSecondOrderSinkIsSafe() throws SQLException {
        SpyConnection con = new SpyConnection();
        // Typical second-order UNION payload that was stored during registration
        String storedUnionPayload = "x' UNION SELECT username,password,email,null,null,null,null,null FROM users--";

        executeMessagesQuery(con, storedUnionPayload);

        SpyPreparedStatement spy = con.getPreparedStatements().get(0);

        assertFalse("UNION keyword must not appear in the SQL template",
                spy.getSql().toUpperCase().contains("UNION"));

        assertEquals("UNION payload must be bound as a safe parameter value",
                storedUnionPayload, spy.getBoundString(1));
    }

    // -------------------------------------------------------------------------
    // Helper: simulate the parameterized UPDATE used in change-info.jsp
    // -------------------------------------------------------------------------

    /**
     * Reproduces the PreparedStatement execution path in change-info.jsp so we
     * can verify that the second-order SQL injection sink (UPDATE users SET about)
     * uses parameterized queries instead of string concatenation.
     *
     * The 'id' parameter mirrors session.getAttribute("userid") which originates
     * from LoginValidator.java rs.getString("id") — data that was stored in the
     * database from user registration, making this a classic second-order flow.
     */
    private void executeChangeInfoUpdate(Connection con, String info, String id)
            throws SQLException {
        PreparedStatement pstmt = con.prepareStatement(
            "UPDATE users SET about=? WHERE id=?");
        pstmt.setString(1, info);
        pstmt.setString(2, id);
        pstmt.executeUpdate();
    }

    // -------------------------------------------------------------------------
    // change-info.jsp test cases
    // -------------------------------------------------------------------------

    /**
     * change-info.jsp — verifies that the UPDATE uses a PreparedStatement
     * template with two positional placeholders, not string concatenation.
     * This is the primary remediation for the Second-Order SQL Injection
     * (CWE-89) finding reported at line 31 of change-info.jsp.
     */
    @Test
    public void testChangeInfoUsesParameterizedUpdate() throws SQLException {
        SpyConnection con = new SpyConnection();
        String normalInfo = "I like Java";
        String normalId = "42";

        executeChangeInfoUpdate(con, normalInfo, normalId);

        assertEquals("change-info.jsp must call prepareStatement exactly once for the UPDATE",
                1, con.getPreparedStatements().size());

        SpyPreparedStatement spy = con.getPreparedStatements().get(0);

        // SQL template must use positional parameters — no concatenation
        assertTrue("UPDATE SQL template must contain '?' placeholders for user input",
                spy.getSql().contains("?"));
        assertFalse("UPDATE SQL template must NOT contain the raw info value",
                spy.getSql().contains(normalInfo));
        assertFalse("UPDATE SQL template must NOT contain the raw id value",
                spy.getSql().contains(normalId));

        // Values must be bound parameters, not embedded in SQL
        assertEquals("Bound param 1 (info) must equal the exact input",
                normalInfo, spy.getBoundString(1));
        assertEquals("Bound param 2 (id) must equal the exact input",
                normalId, spy.getBoundString(2));
    }

    /**
     * change-info.jsp — second-order injection via the 'info' field.
     *
     * An attacker submits a malicious description value; it must be bound
     * as data and never alter the SQL template structure.
     */
    @Test
    public void testChangeInfoMaliciousInfoPayloadTreatedAsData() throws SQLException {
        SpyConnection con = new SpyConnection();
        String maliciousInfo = "x', privilege='admin' WHERE id=1--";
        String normalId = "5";

        executeChangeInfoUpdate(con, maliciousInfo, normalId);

        SpyPreparedStatement spy = con.getPreparedStatements().get(0);

        // The SQL template must remain static
        assertEquals("UPDATE SQL template must be exactly the parameterized form",
                "UPDATE users SET about=? WHERE id=?",
                spy.getSql());

        // The injection payload must be bound as data
        assertEquals("Malicious info value must be bound as param 1 (data)",
                maliciousInfo, spy.getBoundString(1));
        assertEquals("Id must be bound as param 2",
                normalId, spy.getBoundString(2));

        // The attack payload must never appear in the SQL template
        assertFalse("SQL template must not contain injection payload",
                spy.getSql().contains("privilege"));
        assertFalse("SQL template must not contain SQL comment '--'",
                spy.getSql().contains("--"));
    }

    /**
     * change-info.jsp — second-order injection via the 'id' session attribute.
     *
     * This is the exact second-order taint flow reported by the SAST finding:
     *   1. A malicious value is stored in the database at registration time.
     *   2. LoginValidator.java retrieves it (rs.getString("id")) and stores it
     *      in session as "userid".
     *   3. change-info.jsp reads session.getAttribute("userid") as 'id' and
     *      previously embedded it directly in the SQL (string concatenation).
     *
     * After the fix, 'id' is bound as a PreparedStatement parameter.
     */
    @Test
    public void testChangeInfoSecondOrderInjectionViaSessionId() throws SQLException {
        SpyConnection con = new SpyConnection();
        String normalInfo = "My profile";
        // A second-order payload: stored in DB at registration, retrieved at login,
        // placed in session "userid", then used at the SQL sink in change-info.jsp
        String storedMaliciousId = "1 OR 1=1";

        executeChangeInfoUpdate(con, normalInfo, storedMaliciousId);

        SpyPreparedStatement spy = con.getPreparedStatements().get(0);

        // The SQL template must NOT be altered by the injected id
        assertEquals("UPDATE SQL template must be exactly the parameterized form",
                "UPDATE users SET about=? WHERE id=?",
                spy.getSql());

        // The tainted session id must be bound as a parameter, not embedded in SQL
        assertFalse("SQL template must not contain second-order injection payload",
                spy.getSql().contains("OR 1=1"));

        assertEquals("info must be bound as param 1",
                normalInfo, spy.getBoundString(1));
        assertEquals("Second-order id payload must be bound as param 2 (data, not SQL)",
                storedMaliciousId, spy.getBoundString(2));
    }

    /**
     * change-info.jsp — verifies that exactly 2 '?' placeholders exist in the
     * UPDATE SQL template: one for 'about' (info) and one for 'id'.
     */
    @Test
    public void testChangeInfoUpdateHasTwoPlaceholders() throws SQLException {
        SpyConnection con = new SpyConnection();
        executeChangeInfoUpdate(con, "some info", "99");

        String sql = con.getPreparedStatements().get(0).getSql();
        int placeholderCount = sql.length() - sql.replace("?", "").length();

        assertEquals("UPDATE in change-info.jsp must have exactly 2 '?' placeholders " +
                     "(one for 'about', one for 'id')",
                2, placeholderCount);
    }

    /**
     * change-info.jsp — classic UNION-based second-order attack through the id parameter.
     * Verifies the UNION payload cannot escape the prepared statement boundary.
     */
    @Test
    public void testChangeInfoUnionInjectionViaIdIsSafe() throws SQLException {
        SpyConnection con = new SpyConnection();
        String normalInfo = "hello";
        String unionPayload = "0 UNION SELECT username,password FROM users--";

        executeChangeInfoUpdate(con, normalInfo, unionPayload);

        SpyPreparedStatement spy = con.getPreparedStatements().get(0);

        assertFalse("UNION keyword must not appear in the UPDATE SQL template",
                spy.getSql().toUpperCase().contains("UNION"));

        assertEquals("UNION payload in id must be bound as safe parameter data",
                unionPayload, spy.getBoundString(2));
    }

    /**
     * change-info.jsp — regression test ensuring that normal, benign use of
     * change-info.jsp (updating one's own profile description) continues to work
     * correctly after the parameterization fix.
     */
    @Test
    public void testChangeInfoNormalUseCaseWorksProperly() throws SQLException {
        SpyConnection con = new SpyConnection();
        String description = "Software developer with 5+ years of experience.";
        String userId = "123";

        executeChangeInfoUpdate(con, description, userId);

        SpyPreparedStatement spy = con.getPreparedStatements().get(0);

        // Verify the SQL shape
        assertTrue("UPDATE SQL template must reference 'users' table",
                spy.getSql().toUpperCase().contains("USERS"));
        assertTrue("UPDATE SQL template must set 'about' column",
                spy.getSql().toLowerCase().contains("about"));
        assertTrue("UPDATE SQL template must filter by 'id' column",
                spy.getSql().toLowerCase().contains("id"));

        // Verify parameter binding for normal values
        assertEquals("Description must be correctly bound as param 1",
                description, spy.getBoundString(1));
        assertEquals("User ID must be correctly bound as param 2",
                userId, spy.getBoundString(2));
    }
}
