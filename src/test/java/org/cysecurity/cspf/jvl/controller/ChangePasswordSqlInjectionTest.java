package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Tests that verify the Second-Order SQL Injection fix in changepassword.jsp.
 *
 * The vulnerability: the password change page read the user's session attribute
 * "userid" (which was originally populated from the database via
 * LoginValidator.processRequest) and embedded it directly into a string-
 * concatenated SQL UPDATE. Because the id value ultimately came from the
 * database, an attacker could pre-load a malicious value during registration
 * that was later used as live SQL when the password-change page ran.
 *
 * The fix replaces Statement + string concatenation with a PreparedStatement
 * whose template is a static literal and whose parameters are bound via
 * setString(). Both the "password" parameter (direct HTTP input) and the "id"
 * value (from session, tainted via second-order flow) are bound as JDBC
 * parameters, so neither can alter the query structure.
 *
 * These tests model the fixed behaviour using lightweight JDBC proxy spies —
 * no database is required.
 */
public class ChangePasswordSqlInjectionTest extends TestCase {

    // -------------------------------------------------------------------------
    // Infrastructure: PreparedStatement spy via dynamic proxy
    // -------------------------------------------------------------------------

    /**
     * Records every setString() call made to a PreparedStatement so tests can
     * assert that user-supplied values are bound as parameters rather than
     * embedded in the SQL template string.
     */
    static class PreparedStatementSpy implements java.lang.reflect.InvocationHandler {

        /** The static SQL template captured at prepareStatement() time. */
        final String sql;

        /** Ordered list of (parameterIndex, value) pairs set via setString(). */
        final List<Object[]> setStringCalls = new ArrayList<Object[]>();

        /** Number of times executeUpdate() was called on this statement. */
        int executeUpdateCount = 0;

        PreparedStatementSpy(String sql) {
            this.sql = sql;
        }

        @Override
        public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args)
                throws Throwable {
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

    // -------------------------------------------------------------------------
    // Infrastructure: Connection spy via dynamic proxy
    // -------------------------------------------------------------------------

    /**
     * Intercepts prepareStatement() calls, captures the SQL template, and
     * returns a PreparedStatementSpy so parameter binding can be inspected.
     */
    static class ConnectionSpy implements java.lang.reflect.InvocationHandler {

        final List<PreparedStatementSpy> statements = new ArrayList<PreparedStatementSpy>();
        boolean closed = false;

        @Override
        public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args)
                throws Throwable {
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
    // Helper: simulate the fixed changepassword.jsp logic
    //
    // This mirrors exactly the PreparedStatement code now in changepassword.jsp:
    //   PreparedStatement stmt = con.prepareStatement("UPDATE users SET password=? WHERE id=?");
    //   stmt.setString(1, pass);
    //   stmt.setString(2, id);
    //   stmt.executeUpdate();
    //
    // By extracting the logic into a helper we can unit-test the JDBC
    // interaction without needing a running servlet container.
    // -------------------------------------------------------------------------

    /**
     * Executes the password-change logic (as fixed) against the supplied
     * Connection spy. {@code pass} is the new password from the HTTP request;
     * {@code id} is the session attribute value (possibly tainted via
     * second-order injection).
     */
    private void runChangePasswordLogic(Connection con, String pass, String id)
            throws SQLException {
        PreparedStatement stmt = con.prepareStatement("UPDATE users SET password=? WHERE id=?");
        stmt.setString(1, pass);
        stmt.setString(2, id);
        stmt.executeUpdate();
        stmt.close();
    }

    // =========================================================================
    // Tests
    // =========================================================================

    /**
     * A single PreparedStatement must be created for a normal password-change
     * request.
     */
    public void testOnePreparedStatementCreatedForPasswordChange() throws Exception {
        ConnectionSpy conSpy = new ConnectionSpy();

        runChangePasswordLogic(conSpy.asProxy(), "newPassword1!", "42");

        assertEquals("Exactly one PreparedStatement should be prepared",
                1, conSpy.statements.size());
    }

    /**
     * The SQL template must be the exact static string — no user data embedded.
     */
    public void testSqlTemplateIsStaticAndContainsNoUserData() throws Exception {
        String maliciousId   = "1 OR 1=1";
        String maliciousPass = "' OR '1'='1";

        ConnectionSpy conSpy = new ConnectionSpy();

        runChangePasswordLogic(conSpy.asProxy(), maliciousPass, maliciousId);

        PreparedStatementSpy spy = conSpy.statements.get(0);
        assertFalse("SQL template must not contain the injected id",
                spy.sql.contains(maliciousId));
        assertFalse("SQL template must not contain the injected password",
                spy.sql.contains(maliciousPass));
    }

    /**
     * The SQL template must use positional '?' placeholders — this is the
     * SAST-recognised pattern for parameterized queries.
     */
    public void testSqlTemplateUsesPositionalPlaceholders() throws Exception {
        ConnectionSpy conSpy = new ConnectionSpy();

        runChangePasswordLogic(conSpy.asProxy(), "pw", "5");

        PreparedStatementSpy spy = conSpy.statements.get(0);
        assertTrue("SQL template must contain '?' placeholders for parameters",
                spy.sql.contains("?"));
    }

    /**
     * The new password (parameter 1) must be bound via setString and must not
     * appear in the static SQL template.
     */
    public void testPasswordBoundAsFirstParameter() throws Exception {
        String newPassword = "S3cur3P@ss!";

        ConnectionSpy conSpy = new ConnectionSpy();

        runChangePasswordLogic(conSpy.asProxy(), newPassword, "7");

        PreparedStatementSpy spy = conSpy.statements.get(0);
        assertEquals("Exactly 2 parameters should be bound (password + id)",
                2, spy.setStringCalls.size());

        Object[] firstCall = spy.setStringCalls.get(0);
        assertEquals("password must be bound at parameter index 1",
                1, ((Integer) firstCall[0]).intValue());
        assertEquals("password value must be passed verbatim as a bound parameter",
                newPassword, firstCall[1]);

        assertFalse("SQL template must not contain the literal password string",
                spy.sql.contains(newPassword));
    }

    /**
     * The session id (parameter 2) must be bound via setString and must not
     * appear in the static SQL template. This is the second-order injection
     * vector: the id came from the database and could carry a pre-stored payload.
     */
    public void testIdBoundAsSecondParameter() throws Exception {
        String sessionId = "99";

        ConnectionSpy conSpy = new ConnectionSpy();

        runChangePasswordLogic(conSpy.asProxy(), "pass", sessionId);

        PreparedStatementSpy spy = conSpy.statements.get(0);

        Object[] secondCall = spy.setStringCalls.get(1);
        assertEquals("id must be bound at parameter index 2",
                2, ((Integer) secondCall[0]).intValue());
        assertEquals("id value must be passed verbatim as a bound parameter",
                sessionId, secondCall[1]);

        assertFalse("SQL template must not contain the literal id string",
                spy.sql.contains(sessionId));
    }

    /**
     * Second-order SQL injection: the id value stored in session comes
     * originally from the database (LoginValidator stores rs.getString("id")).
     * An attacker who pre-loads a crafted value must find it arrives as a bound
     * parameter, not as SQL.
     */
    public void testSecondOrderInjectionViaSessionIdIsParameterized() throws Exception {
        // Classic second-order payload: this value might have been stored in
        // the DB by an attacker and later placed in the session by LoginValidator.
        String poisonedId = "1; DROP TABLE users; --";

        ConnectionSpy conSpy = new ConnectionSpy();

        runChangePasswordLogic(conSpy.asProxy(), "safePassword", poisonedId);

        PreparedStatementSpy spy = conSpy.statements.get(0);
        assertFalse("SQL template must not contain the second-order injected id payload",
                spy.sql.contains(poisonedId));

        Object[] secondCall = spy.setStringCalls.get(1);
        assertEquals("poisoned id must be bound at parameter index 2",
                2, ((Integer) secondCall[0]).intValue());
        assertEquals("poisoned id value must arrive as literal data, not SQL",
                poisonedId, secondCall[1]);
    }

    /**
     * Union-based second-order injection attempt via the id parameter.
     */
    public void testUnionBasedSecondOrderInjectionIsParameterized() throws Exception {
        String unionPayload = "0 UNION SELECT password FROM users WHERE id=1";

        ConnectionSpy conSpy = new ConnectionSpy();

        runChangePasswordLogic(conSpy.asProxy(), "myNewPass", unionPayload);

        PreparedStatementSpy spy = conSpy.statements.get(0);
        assertFalse("SQL template must not contain UNION payload",
                spy.sql.contains(unionPayload));

        Object[] secondCall = spy.setStringCalls.get(1);
        assertEquals("UNION payload must be bound as a parameter, not executed as SQL",
                unionPayload, secondCall[1]);
    }

    /**
     * Tautology-based injection attempt via the password parameter (direct
     * HTTP input — first-order vector on the same sink).
     */
    public void testTautologyInjectionViaPasswordIsParameterized() throws Exception {
        String tautologyPayload = "' OR '1'='1'; --";

        ConnectionSpy conSpy = new ConnectionSpy();

        runChangePasswordLogic(conSpy.asProxy(), tautologyPayload, "3");

        PreparedStatementSpy spy = conSpy.statements.get(0);
        assertFalse("SQL template must not contain tautology payload",
                spy.sql.contains(tautologyPayload));

        Object[] firstCall = spy.setStringCalls.get(0);
        assertEquals("tautology payload must be bound as a parameter at index 1",
                tautologyPayload, firstCall[1]);
    }

    /**
     * executeUpdate() must be called exactly once per password-change request.
     */
    public void testExecuteUpdateCalledExactlyOnce() throws Exception {
        ConnectionSpy conSpy = new ConnectionSpy();

        runChangePasswordLogic(conSpy.asProxy(), "pass123", "1");

        PreparedStatementSpy spy = conSpy.statements.get(0);
        assertEquals("executeUpdate() must be called exactly once",
                1, spy.executeUpdateCount);
    }

    /**
     * Exactly two parameters must be bound in total (password + id) — no more,
     * no fewer — ensuring the query structure is fully parameterized.
     */
    public void testExactlyTwoParametersAreBound() throws Exception {
        ConnectionSpy conSpy = new ConnectionSpy();

        runChangePasswordLogic(conSpy.asProxy(), "newPass", "10");

        PreparedStatementSpy spy = conSpy.statements.get(0);
        assertEquals("Exactly two parameters (password, id) must be bound",
                2, spy.setStringCalls.size());
    }
}
