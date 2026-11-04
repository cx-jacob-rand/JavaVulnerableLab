package org.cysecurity.cspf.jvl.security;

import junit.framework.TestCase;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * Regression test for CWE-89 in myprofile.jsp: the "id" request parameter must
 * not be concatenated into the "cards" query; it has to be bound through a
 * PreparedStatement parameter instead.
 *
 * JSPs cannot be executed in a plain JUnit run, so the page source is inspected.
 */
public class MyProfileSqlInjectionTest extends TestCase {

    private String jsp;

    protected void setUp() throws IOException {
        File f = new File("src/main/webapp/myprofile.jsp");
        jsp = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
    }

    public void testCardsQueryUsesPlaceholder() {
        assertTrue("cards query must be a prepared statement with a placeholder",
                jsp.contains("prepareStatement(\"select * from cards where id=?\")"));
    }

    public void testIdIsBoundAsParameter() {
        assertTrue("id must be bound via setString", jsp.contains("cardStmt.setString(1, id)"));
        assertTrue("prepared statement must be executed without SQL text",
                jsp.contains("cardStmt.executeQuery()"));
    }

    public void testCardsQueryIsNotConcatenated() {
        assertFalse("cards query must not concatenate the id parameter",
                jsp.contains("from cards where id=\"+id"));
        assertFalse("cards query must not be run through a plain Statement",
                jsp.contains("stmt.executeQuery(\"select * from cards"));
    }

    public void testPreparedStatementIsImported() {
        assertTrue(jsp.contains("import=\"java.sql.PreparedStatement\""));
    }
}
