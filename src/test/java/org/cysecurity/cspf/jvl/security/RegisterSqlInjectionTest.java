package org.cysecurity.cspf.jvl.security;

import junit.framework.TestCase;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cysecurity.cspf.jvl.controller.Register;

/**
 * Tests that the Register servlet no longer builds its INSERT statements by
 * concatenating the "username" (and other) request parameters (CWE-89), and
 * uses PreparedStatement parameter binding instead.
 *
 * The real Register servlet is exercised. The database is replaced by a
 * recording JDBC driver that is reached through the servlet's normal
 * DBConnect / DriverManager path.
 */
public class RegisterSqlInjectionTest extends TestCase {

    private static final String INJECTION = "x'); DROP TABLE users; --";

    /** One recorded prepareStatement call. */
    static class Recorded {
        final String sql;
        final Map<Integer, String> params = new HashMap<Integer, String>();
        boolean executed = false;

        Recorded(String sql) {
            this.sql = sql;
        }
    }

    /** Recording JDBC driver registered when DBConnect loads this class by name. */
    public static class SpyDriver implements Driver {
        static final List<Recorded> prepared = new ArrayList<Recorded>();
        static final List<String> plainStatements = new ArrayList<String>();

        static {
            try {
                DriverManager.registerDriver(new SpyDriver());
            } catch (SQLException e) {
                throw new ExceptionInInitializerError(e);
            }
        }

        static void reset() {
            prepared.clear();
            plainStatements.clear();
        }

        public Connection connect(String url, Properties info) throws SQLException {
            if (!acceptsURL(url)) {
                return null;
            }
            return (Connection) Proxy.newProxyInstance(
                    SpyDriver.class.getClassLoader(), new Class<?>[] {Connection.class},
                    new InvocationHandler() {
                        public Object invoke(Object proxy, Method m, Object[] args) {
                            String name = m.getName();
                            if (name.equals("prepareStatement")) {
                                final Recorded rec = new Recorded((String) args[0]);
                                prepared.add(rec);
                                return preparedStatement(rec);
                            }
                            if (name.equals("createStatement")) {
                                plainStatements.add("createStatement");
                            }
                            return defaultValue(m.getReturnType());
                        }
                    });
        }

        private static PreparedStatement preparedStatement(final Recorded rec) {
            return (PreparedStatement) Proxy.newProxyInstance(
                    SpyDriver.class.getClassLoader(), new Class<?>[] {PreparedStatement.class},
                    new InvocationHandler() {
                        public Object invoke(Object proxy, Method m, Object[] args) {
                            String name = m.getName();
                            if (name.equals("setString")) {
                                rec.params.put((Integer) args[0], (String) args[1]);
                            } else if (name.equals("executeUpdate")) {
                                rec.executed = true;
                                return Integer.valueOf(1);
                            }
                            return defaultValue(m.getReturnType());
                        }
                    });
        }

        public boolean acceptsURL(String url) {
            return url != null && url.startsWith("jdbc:spy:");
        }

        public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) {
            return new DriverPropertyInfo[0];
        }

        public int getMajorVersion() { return 1; }
        public int getMinorVersion() { return 0; }
        public boolean jdbcCompliant() { return false; }
        public Logger getParentLogger() { return Logger.getLogger("spy"); }
    }

    static Object defaultValue(Class<?> type) {
        if (type == boolean.class) return Boolean.FALSE;
        if (type == int.class) return Integer.valueOf(0);
        if (type == long.class) return Long.valueOf(0L);
        return null;
    }

    /** Servlet under test; only getServletContext is stubbed. */
    static class TestableRegister extends Register {
        private final String configPath;

        TestableRegister(String configPath) {
            this.configPath = configPath;
        }

        public ServletContext getServletContext() {
            return (ServletContext) Proxy.newProxyInstance(
                    getClass().getClassLoader(), new Class<?>[] {ServletContext.class},
                    new InvocationHandler() {
                        public Object invoke(Object proxy, Method m, Object[] args) {
                            if (m.getName().equals("getRealPath")) {
                                return configPath;
                            }
                            return defaultValue(m.getReturnType());
                        }
                    });
        }

        void run(HttpServletRequest req, HttpServletResponse resp) throws Exception {
            processRequest(req, resp);
        }
    }

    private File configFile;
    private final List<String> redirects = new ArrayList<String>();

    protected void setUp() throws Exception {
        SpyDriver.reset();
        redirects.clear();
        configFile = File.createTempFile("jvl-config", ".properties");
        Properties p = new Properties();
        p.setProperty("dburl", "jdbc:spy:");
        p.setProperty("dbname", "test");
        p.setProperty("dbuser", "u");
        p.setProperty("dbpass", "p");
        p.setProperty("jdbcdriver", SpyDriver.class.getName());
        FileOutputStream out = new FileOutputStream(configFile);
        try {
            p.store(out, null);
        } finally {
            out.close();
        }
    }

    protected void tearDown() {
        configFile.delete();
    }

    private HttpServletRequest request(final Map<String, String> params) {
        return (HttpServletRequest) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] {HttpServletRequest.class},
                new InvocationHandler() {
                    public Object invoke(Object proxy, Method m, Object[] args) {
                        if (m.getName().equals("getParameter")) {
                            return params.get((String) args[0]);
                        }
                        return defaultValue(m.getReturnType());
                    }
                });
    }

    private HttpServletResponse response() {
        final PrintWriter writer = new PrintWriter(new StringWriter());
        return (HttpServletResponse) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] {HttpServletResponse.class},
                new InvocationHandler() {
                    public Object invoke(Object proxy, Method m, Object[] args) throws IOException {
                        if (m.getName().equals("getWriter")) {
                            return writer;
                        }
                        if (m.getName().equals("sendRedirect")) {
                            redirects.add((String) args[0]);
                        }
                        return defaultValue(m.getReturnType());
                    }
                });
    }

    private Map<String, String> params(String username) {
        Map<String, String> p = new HashMap<String, String>();
        p.put("username", username);
        p.put("password", "pw");
        p.put("email", "a@b.c");
        p.put("About", "about me");
        p.put("secret", "s3cret");
        return p;
    }

    private void register(String username) throws Exception {
        new TestableRegister(configFile.getAbsolutePath()).run(request(params(username)), response());
    }

    public void testBenignRegistrationStillWorks() throws Exception {
        register("alice");

        assertEquals("users and UserMessages inserts expected", 2, SpyDriver.prepared.size());
        Recorded users = SpyDriver.prepared.get(0);
        Recorded msgs = SpyDriver.prepared.get(1);
        assertTrue(users.sql.startsWith("INSERT into users"));
        assertTrue(msgs.sql.startsWith("INSERT into UserMessages"));
        assertEquals("alice", users.params.get(1));
        assertEquals("pw", users.params.get(2));
        assertEquals("a@b.c", users.params.get(3));
        assertEquals("about me", users.params.get(4));
        assertEquals("s3cret", users.params.get(5));
        assertEquals("alice", msgs.params.get(1));
        assertTrue(users.executed);
        assertTrue(msgs.executed);
        assertEquals("index.jsp", redirects.get(0));
    }

    public void testUsernamePayloadIsBoundNotConcatenated() throws Exception {
        register(INJECTION);

        assertEquals(2, SpyDriver.prepared.size());
        for (Recorded rec : SpyDriver.prepared) {
            assertFalse("SQL text must not contain the payload", rec.sql.contains("DROP TABLE"));
            assertFalse("SQL text must not contain the payload", rec.sql.contains(INJECTION));
            assertTrue("SQL must use placeholders", rec.sql.contains("?"));
            assertEquals("Payload must be bound as plain data", INJECTION, rec.params.get(1));
            assertTrue(rec.executed);
        }
    }

    public void testNoStringConcatenatedStatementIsUsed() throws Exception {
        register("bob' OR '1'='1");

        assertTrue("Statement (non-prepared) must not be used", SpyDriver.plainStatements.isEmpty());
    }

    public void testOtherParametersAreBoundToo() throws Exception {
        Map<String, String> p = params("carol");
        p.put("password", "pw'); --");
        p.put("email", "e'); --");
        p.put("About", "a'); --");
        p.put("secret", "z'); --");
        new TestableRegister(configFile.getAbsolutePath()).run(request(p), response());

        Recorded users = SpyDriver.prepared.get(0);
        assertFalse(users.sql.contains("--"));
        assertEquals("pw'); --", users.params.get(2));
        assertEquals("e'); --", users.params.get(3));
        assertEquals("a'); --", users.params.get(4));
        assertEquals("z'); --", users.params.get(5));
    }

    public void testMissingSecretDefaultsToNosecret() throws Exception {
        Map<String, String> p = params("dave");
        p.remove("secret");
        new TestableRegister(configFile.getAbsolutePath()).run(request(p), response());

        assertEquals("nosecret", SpyDriver.prepared.get(0).params.get(5));
    }
}
