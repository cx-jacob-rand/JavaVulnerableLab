package org.cysecurity.cspf.jvl.security;

import junit.framework.TestCase;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * Regression test for CWE-89 (second-order SQL injection) in
 * vulnerability/csrf/change-info.jsp: the session user id (originating from the
 * database) and the "info" parameter must be bound through PreparedStatement
 * parameters instead of being concatenated into the UPDATE statement.
 *
 * JSPs cannot be executed in a plain JUnit run, so the page source is inspected.
 */
public class ChangeInfoSqlInjectionTest extends TestCase {

    private String jsp;

    protected void setUp() throws IOException {
        File f = new File("src/main/webapp/vulnerability/csrf/change-info.jsp");
        jsp = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
    }

    public void testUpdateUsesPlaceholders() {
        assertTrue("update must be a prepared statement with placeholders",
                jsp.contains("prepareStatement(\"Update users set about=? where id=?\")"));
    }

    public void testValuesAreBoundAsParameters() {
        assertTrue("info must be bound via setString", jsp.contains("updateStmt.setString(1, info)"));
        assertTrue("id must be bound via setString", jsp.contains("updateStmt.setString(2, id)"));
        assertTrue("prepared statement must be executed without SQL text",
                jsp.contains("updateStmt.executeUpdate()"));
    }

    public void testUpdateIsNotConcatenated() {
        assertFalse("update must not concatenate the info parameter",
                jsp.contains("about='\"+info"));
        assertFalse("update must not concatenate the id",
                jsp.contains("where id=\"+id"));
        assertFalse("no plain Statement should be created",
                jsp.contains("con.createStatement()"));
    }

    public void testPreparedStatementIsImported() {
        assertTrue(jsp.contains("import=\"java.sql.PreparedStatement\""));
    }
}
