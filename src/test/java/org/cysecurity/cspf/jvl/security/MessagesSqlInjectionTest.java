package org.cysecurity.cspf.jvl.security;

import junit.framework.TestCase;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * Regression test for CWE-89 (second-order SQL injection) in
 * vulnerability/Messages.jsp: the session user name (originating from the
 * database) must be bound through a PreparedStatement parameter instead of
 * being concatenated into the SELECT statement.
 *
 * JSPs cannot be executed in a plain JUnit run, so the page source is inspected.
 */
public class MessagesSqlInjectionTest extends TestCase {

    private String jsp;

    protected void setUp() throws IOException {
        File f = new File("src/main/webapp/vulnerability/Messages.jsp");
        jsp = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
    }

    public void testQueryUsesPlaceholder() {
        assertTrue("query must be a prepared statement with a placeholder",
                jsp.contains("prepareStatement(\"select * from UserMessages where recipient=?\")"));
    }

    public void testRecipientIsBoundAsParameter() {
        assertTrue("recipient must be bound via setString",
                jsp.contains("stmt.setString(1, String.valueOf(session.getAttribute(\"user\")))"));
        assertTrue("prepared statement must be executed without SQL text",
                jsp.contains("stmt.executeQuery()"));
    }

    public void testQueryIsNotConcatenated() {
        assertFalse("query must not concatenate the session user",
                jsp.contains("recipient='\"+"));
        assertFalse("no plain Statement should be created",
                jsp.contains("con.createStatement()"));
    }

    public void testPreparedStatementIsImported() {
        assertTrue(jsp.contains("import=\"java.sql.PreparedStatement\""));
    }
}
