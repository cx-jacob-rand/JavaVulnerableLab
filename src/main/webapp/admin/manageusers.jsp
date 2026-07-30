 <%@ include file="/header.jsp" %>
  <%@page import="java.sql.PreparedStatement"%>
<%@page import="java.sql.ResultSet"%>
<%@page import="java.sql.SQLException"%>
<%@page import="org.cysecurity.cspf.jvl.model.DBConnect"%>
<%@page import="java.sql.Connection"%>

 <%
   Connection con=new DBConnect().connect(getServletContext().getRealPath("/WEB-INF/config.properties"));
 if(request.getParameter("delete")!=null)
 {
     String user=request.getParameter("user");
     // Use PreparedStatement to prevent SQL injection
     PreparedStatement deleteStmt = con.prepareStatement(
         "DELETE FROM users WHERE username=?");
     deleteStmt.setString(1, user);
     deleteStmt.executeUpdate();
 }
 %>
<form action="manageusers.jsp" method="POST">
<%
 // Static query with no user input - Statement is safe here
 PreparedStatement selectStmt = con.prepareStatement(
     "SELECT * FROM users WHERE privilege='user'");
 ResultSet rs=selectStmt.executeQuery();
 while(rs.next())
 {
     out.print("<input type='radio' name='user' value='"+rs.getString("username")+"'/> "+rs.getString("username")+"<br/>");
 }
 %>
<br/>
<input type="submit" value="Delete" name="delete"/>

</form>
<br/>
<a href="admin.jsp"> Back to Admin Panel</a>
 <%@ include file="/footer.jsp" %>