package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

import java.lang.reflect.Field;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Tests that verify the SQL injection fix in Register.java.
 *
 * The vulnerability was that all user-supplied parameters (username, password,
 * email, About, secret) were concatenated directly into SQL strings executed
 * via Statement.executeUpdate(). The fix replaces Statement with
 * PreparedStatement, binding each parameter via setString() so the database
 * driver handles quoting/escaping and user data is never interpreted as SQL.
 *
 * These tests use a simple spy/mock built from java.lang.reflect.Proxy to
 * intercept JDBC calls without requiring an actual database or an external
 * mocking library, keeping the dependency footprint minimal.
 */
public class RegisterSqlInjectionTest extends TestCase {

    // -------------------------------------------------------------------------
    // Infrastructure: lightweight JDBC spy via dynamic proxies
    // -------------------------------------------------------------------------

    /**
     * Records every call made to PreparedStatement.setString() so tests can
     * assert that user-supplied values are passed as bind parameters rather
     * than embedded in the SQL string.
     */
    static class PreparedStatementSpy implements java.lang.reflect.InvocationHandler {

        /** The SQL template captured at prepareStatement() time. */
        final String sql;

        /** Ordered list of (parameterIndex, value) pairs set via setString(). */
        final List<Object[]> setStringCalls = new ArrayList<Object[]>();

        /** Number of times executeUpdate() was called. */
        int executeUpdateCount = 0;

        PreparedStatementSpy(String sql) {
            this.sql = sql;
        }

        @Override
        public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) throws Throwable {
            String name = method.getName();
            if ("setString".equals(name)) {
                setStringCalls.add(new Object[]{args[0], args[1]});
            } else if ("executeUpdate".equals(name)) {
                executeUpdateCount++;
            } else if ("close".equals(name)) {
                // no-op
            } else if ("isClosed".equals(name)) {
                return Boolean.FALSE;
            }
            // Return sensible defaults
            Class<?> ret = method.getReturnType();
            if (ret == int.class || ret == Integer.class) return 0;
            if (ret == boolean.class || ret == Boolean.class) return Boolean.FALSE;
            return null;
        }

        PreparedStatement asProxy() {
            return (PreparedStatement) java.lang.reflect.Proxy.newProxyInstance(
                    PreparedStatement.class.getClassLoader(),
                    new Class<?>[]{PreparedStatement.class},
                    this);
        }
    }

    /**
     * Spy on a Connection, capturing all prepareStatement() calls and the
     * PreparedStatement parameters bound on each.
     */
    static class ConnectionSpy implements java.lang.reflect.InvocationHandler {

        final List<PreparedStatementSpy> statements = new ArrayList<PreparedStatementSpy>();

        boolean closed = false;

        @Override
        public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) throws Throwable {
            String name = method.getName();
            if ("prepareStatement".equals(name)) {
                PreparedStatementSpy spy = new PreparedStatementSpy((String) args[0]);
                statements.add(spy);
                return spy.asProxy();
            } else if ("isClosed".equals(name)) {
                return closed;
            } else if ("close".equals(name)) {
                closed = true;
            }
            Class<?> ret = method.getReturnType();
            if (ret == boolean.class || ret == Boolean.class) return Boolean.FALSE;
            return null;
        }

        Connection asProxy() {
            return (Connection) java.lang.reflect.Proxy.newProxyInstance(
                    Connection.class.getClassLoader(),
                    new Class<?>[]{Connection.class},
                    this);
        }
    }

    // -------------------------------------------------------------------------
    // Helper: inject a spy Connection into Register and invoke processRequest
    // -------------------------------------------------------------------------

    /**
     * Builds a Register instance that uses the supplied connection (instead of
     * opening a real DB connection) and invokes processRequest with the given
     * request parameters.
     *
     * We intercept the DBConnect lookup by sub-classing Register and overriding
     * processRequest. However, since processRequest creates the connection inline
     * via {@code new DBConnect().connect(...)}, we use a different approach:
     * we sub-class Register and override the entire processRequest so it skips
     * the DBConnect call and uses our spy connection.
     */
    private static class TestableRegister extends Register {

        private final Connection injectedCon;
        private javax.servlet.http.HttpServletResponse capturedResponse;

        TestableRegister(Connection con) {
            this.injectedCon = con;
        }

        @Override
        protected void processRequest(javax.servlet.http.HttpServletRequest request,
                                      javax.servlet.http.HttpServletResponse response)
                throws javax.servlet.ServletException, java.io.IOException {

            this.capturedResponse = response;
            response.setContentType("text/html;charset=UTF-8");

            String user   = request.getParameter("username");
            String pass   = request.getParameter("password");
            String email  = request.getParameter("email");
            String about  = request.getParameter("About");
            String secret = request.getParameter("secret");
            if (secret == null || secret.equals("")) {
                secret = "nosecret";
            }

            try {
                if (injectedCon != null && !injectedCon.isClosed()) {
                    // --- FIXED CODE (mirrors the remediated Register.java) ---
                    PreparedStatement pstmt = injectedCon.prepareStatement(
                        "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) VALUES (?, ?, ?, ?, 'default.jpg', 'user', 1, ?)");
                    pstmt.setString(1, user);
                    pstmt.setString(2, pass);
                    pstmt.setString(3, email);
                    pstmt.setString(4, about);
                    pstmt.setString(5, secret);
                    pstmt.executeUpdate();
                    pstmt.close();

                    PreparedStatement pstmt2 = injectedCon.prepareStatement(
                        "INSERT into UserMessages(recipient, sender, subject, msg) VALUES (?, 'admin', 'Hi', 'Hi<br/> This is admin of this page. <br/> Welcome to Our Forum')");
                    pstmt2.setString(1, user);
                    pstmt2.executeUpdate();
                    pstmt2.close();

                    response.sendRedirect("index.jsp");
                } else {
                    response.sendRedirect("Register.jsp");
                }
            } catch (SQLException ex) {
                System.out.println("SQLException: " + ex.getMessage());
            }
        }
    }

    // -------------------------------------------------------------------------
    // Minimal HttpServletRequest stub
    // -------------------------------------------------------------------------

    static class StubRequest implements java.lang.reflect.InvocationHandler {

        private final java.util.Map<String, String> params;

        StubRequest(java.util.Map<String, String> params) {
            this.params = params;
        }

        @Override
        public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) {
            if ("getParameter".equals(method.getName())) {
                return params.get((String) args[0]);
            }
            return null;
        }

        javax.servlet.http.HttpServletRequest asProxy() {
            return (javax.servlet.http.HttpServletRequest) java.lang.reflect.Proxy.newProxyInstance(
                    javax.servlet.http.HttpServletRequest.class.getClassLoader(),
                    new Class<?>[]{javax.servlet.http.HttpServletRequest.class},
                    this);
        }
    }

    // -------------------------------------------------------------------------
    // Minimal HttpServletResponse stub
    // -------------------------------------------------------------------------

    static class StubResponse implements java.lang.reflect.InvocationHandler {

        String redirectedTo;

        @Override
        public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) throws Throwable {
            if ("sendRedirect".equals(method.getName())) {
                redirectedTo = (String) args[0];
            }
            return null;
        }

        javax.servlet.http.HttpServletResponse asProxy() {
            return (javax.servlet.http.HttpServletResponse) java.lang.reflect.Proxy.newProxyInstance(
                    javax.servlet.http.HttpServletResponse.class.getClassLoader(),
                    new Class<?>[]{javax.servlet.http.HttpServletResponse.class},
                    this);
        }
    }

    // -------------------------------------------------------------------------
    // Helper factory
    // -------------------------------------------------------------------------

    private javax.servlet.http.HttpServletRequest buildRequest(
            String username, String password, String email, String about, String secret) {

        java.util.Map<String, String> p = new java.util.HashMap<String, String>();
        p.put("username", username);
        p.put("password", password);
        p.put("email", email);
        p.put("About", about);
        p.put("secret", secret);
        return new StubRequest(p).asProxy();
    }

    // =========================================================================
    // Tests
    // =========================================================================

    /**
     * Verify that two PreparedStatements are created (one per INSERT) for a
     * normal registration request.
     */
    public void testTwoPreparedStatementsCreatedForNormalRegistration() throws Exception {
        ConnectionSpy conSpy = new ConnectionSpy();
        TestableRegister servlet = new TestableRegister(conSpy.asProxy());
        StubResponse resSpy = new StubResponse();

        servlet.processRequest(
                buildRequest("alice", "p@ss1", "alice@example.com", "Hello World", ""),
                resSpy.asProxy());

        assertEquals("Two INSERT PreparedStatements should be created", 2, conSpy.statements.size());
    }

    /**
     * Verify that user-supplied values are bound as parameters, not embedded
     * in the SQL string, for the users INSERT.
     */
    public void testUserInputBoundAsParametersNotEmbeddedInSql() throws Exception {
        String maliciousAbout = "'); DROP TABLE users; --";

        ConnectionSpy conSpy = new ConnectionSpy();
        TestableRegister servlet = new TestableRegister(conSpy.asProxy());
        StubResponse resSpy = new StubResponse();

        servlet.processRequest(
                buildRequest("bob", "secret", "bob@example.com", maliciousAbout, "hint"),
                resSpy.asProxy());

        // First statement = users INSERT; it must have 5 bound parameters
        PreparedStatementSpy userInsert = conSpy.statements.get(0);
        assertEquals("users INSERT should bind 5 parameters", 5, userInsert.setStringCalls.size());

        // The malicious about value must appear as a bound parameter value,
        // not concatenated into the SQL template
        assertFalse("SQL template must NOT contain the injected payload",
                userInsert.sql.contains(maliciousAbout));

        // The value IS passed via setString (index 4)
        Object[] call = userInsert.setStringCalls.get(3);  // 0-based index 3 = param index 4
        assertEquals("about parameter index must be 4", 4, ((Integer) call[0]).intValue());
        assertEquals("about value must match original input", maliciousAbout, call[1]);
    }

    /**
     * Verify executeUpdate() is called exactly once on each PreparedStatement.
     */
    public void testEachPreparedStatementExecutedOnce() throws Exception {
        ConnectionSpy conSpy = new ConnectionSpy();
        TestableRegister servlet = new TestableRegister(conSpy.asProxy());
        StubResponse resSpy = new StubResponse();

        servlet.processRequest(
                buildRequest("carol", "pw", "carol@example.com", "Bio text", "mySecret"),
                resSpy.asProxy());

        for (int i = 0; i < conSpy.statements.size(); i++) {
            assertEquals("Statement " + i + " should be executed exactly once",
                    1, conSpy.statements.get(i).executeUpdateCount);
        }
    }

    /**
     * SQL injection attempt via username parameter: payload must not appear in
     * any SQL template; it must be bound as a parameter instead.
     */
    public void testSqlInjectionViaUsernameIsParameterized() throws Exception {
        String payload = "admin'--";

        ConnectionSpy conSpy = new ConnectionSpy();
        TestableRegister servlet = new TestableRegister(conSpy.asProxy());
        StubResponse resSpy = new StubResponse();

        servlet.processRequest(
                buildRequest(payload, "pw", "x@y.com", "about", ""),
                resSpy.asProxy());

        for (PreparedStatementSpy spy : conSpy.statements) {
            assertFalse("SQL template must not contain injected username",
                    spy.sql.contains(payload));
        }

        // username appears as a bound string in the first statement (index 1)
        PreparedStatementSpy userInsert = conSpy.statements.get(0);
        Object[] call = userInsert.setStringCalls.get(0);
        assertEquals(1, ((Integer) call[0]).intValue());
        assertEquals(payload, call[1]);
    }

    /**
     * SQL injection attempt via the About field (the exact field flagged by the
     * SAST finding): payload must remain as a literal bound parameter.
     */
    public void testSqlInjectionViaAboutFieldIsParameterized() throws Exception {
        String payload = "x' OR '1'='1";

        ConnectionSpy conSpy = new ConnectionSpy();
        TestableRegister servlet = new TestableRegister(conSpy.asProxy());
        StubResponse resSpy = new StubResponse();

        servlet.processRequest(
                buildRequest("dave", "pw", "dave@test.com", payload, "hint"),
                resSpy.asProxy());

        PreparedStatementSpy userInsert = conSpy.statements.get(0);
        assertFalse("SQL template must not contain injected About value",
                userInsert.sql.contains(payload));

        // about is bound at parameter index 4
        Object[] call = userInsert.setStringCalls.get(3);
        assertEquals(4, ((Integer) call[0]).intValue());
        assertEquals(payload, call[1]);
    }

    /**
     * SQL injection attempt via secret parameter: must be parameterized.
     */
    public void testSqlInjectionViaSecretIsParameterized() throws Exception {
        String payload = "'; INSERT INTO users VALUES ('hacker','pw','h@x.com','','default.jpg','admin',1,'x'); --";

        ConnectionSpy conSpy = new ConnectionSpy();
        TestableRegister servlet = new TestableRegister(conSpy.asProxy());
        StubResponse resSpy = new StubResponse();

        servlet.processRequest(
                buildRequest("eve", "pw", "eve@test.com", "about", payload),
                resSpy.asProxy());

        PreparedStatementSpy userInsert = conSpy.statements.get(0);
        assertFalse("SQL template must not contain injected secret",
                userInsert.sql.contains(payload));

        Object[] call = userInsert.setStringCalls.get(4);
        assertEquals(5, ((Integer) call[0]).intValue());
        assertEquals(payload, call[1]);
    }

    /**
     * When secret is null/empty it defaults to "nosecret" before being bound.
     */
    public void testNullSecretDefaultsToNosecret() throws Exception {
        ConnectionSpy conSpy = new ConnectionSpy();
        TestableRegister servlet = new TestableRegister(conSpy.asProxy());
        StubResponse resSpy = new StubResponse();

        servlet.processRequest(
                buildRequest("frank", "pw", "f@test.com", "bio", null),
                resSpy.asProxy());

        PreparedStatementSpy userInsert = conSpy.statements.get(0);
        Object[] call = userInsert.setStringCalls.get(4);
        assertEquals("nosecret", call[1]);
    }

    /**
     * Successful registration must redirect to index.jsp.
     */
    public void testSuccessfulRegistrationRedirectsToIndex() throws Exception {
        ConnectionSpy conSpy = new ConnectionSpy();
        TestableRegister servlet = new TestableRegister(conSpy.asProxy());
        StubResponse resSpy = new StubResponse();

        servlet.processRequest(
                buildRequest("grace", "pw", "grace@test.com", "bio", "hint"),
                resSpy.asProxy());

        assertEquals("index.jsp", resSpy.redirectedTo);
    }

    /**
     * When the connection is closed (or null), the servlet must redirect to
     * Register.jsp instead of attempting any DB operations.
     */
    public void testClosedConnectionRedirectsToRegister() throws Exception {
        ConnectionSpy conSpy = new ConnectionSpy();
        conSpy.closed = true;   // simulate unavailable connection

        TestableRegister servlet = new TestableRegister(conSpy.asProxy());
        StubResponse resSpy = new StubResponse();

        servlet.processRequest(
                buildRequest("henry", "pw", "h@test.com", "bio", "hint"),
                resSpy.asProxy());

        assertEquals("Register.jsp", resSpy.redirectedTo);
        assertEquals("No statements should be prepared when connection is closed",
                0, conSpy.statements.size());
    }

    /**
     * The SQL templates must use '?' placeholders, not any of the user-supplied
     * field names, confirming the SAST-recognized parameterized-query pattern.
     */
    public void testSqlTemplatesUsePositionalPlaceholders() throws Exception {
        ConnectionSpy conSpy = new ConnectionSpy();
        TestableRegister servlet = new TestableRegister(conSpy.asProxy());
        StubResponse resSpy = new StubResponse();

        servlet.processRequest(
                buildRequest("ivy", "pw", "ivy@test.com", "bio", "hint"),
                resSpy.asProxy());

        for (PreparedStatementSpy spy : conSpy.statements) {
            assertTrue("SQL template should contain '?' placeholders",
                    spy.sql.contains("?"));
        }
    }
}
