<%@ page import="org.apache.logging.log4j.LogManager,org.apache.logging.log4j.Logger" %>
<%
  Logger logger = LogManager.getLogger("VulnJSP");
  String q    = request.getParameter("q");
  String xapi = request.getHeader("X-Api");

  if (q != null)    logger.error("q=" + q);
  if (xapi != null) logger.error("X-Api=" + xapi);

  out.println("OK");
%>
