<%@ page import="org.apache.logging.log4j.LogManager" %>
<%@ page import="org.apache.logging.log4j.Logger" %>
<%
    // Ottiene un logger
    Logger logger = LogManager.getLogger("VulnJSP");

    // Prende un parametro dalla richiesta HTTP, ad esempio 'input'
    String userInput = request.getParameter("input");

    // Se il parametro esiste, lo logga (questa è la vulnerabilità!)
    if (userInput != null) {
        logger.error("User input received: " + userInput);
        out.println("<h1>Logged your input: " + userInput + "</h1>");
    } else {
        out.println("<h1>Provide an 'input' parameter to be logged.</h1>");
    }
%>
