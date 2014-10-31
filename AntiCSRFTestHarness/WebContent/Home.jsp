<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ taglib uri="/WEB-INF/anticsrf.tld" prefix="csrf" %>
<%@ page import="com.gdssecurity.anticsrf.utils.ConfigUtil" %>

<html>
<h1>CSRF Protection Test Harness 
<%
if(ConfigUtil.isHmacMode()){
	out.println("(HMAC Protection Mode)");
}
else{
	out.println("(SESSION Protection Mode)");
}
%>
</h1>

<h2>AntiCSRF Filter Test Harness</h2>
<br />

<a href="filter/SiteWideServlet?<csrf:forRequest />&user=${user}">Click me for Site-wide token protection</a><br />
<a href="filter/URLSpecificServlet?<csrf:forRequestUrlSpecific url='/filter/URLSpecificServlet' />&user=${user}" />Click me for URL Specific protection</a><br />
<%if(ConfigUtil.isSessionMode()){ %>
<a href="filter/OneTimeUseServlet?<csrf:forRequestUrlSpecific url='/filter/OneTimeUseServlet' />&user=${user}" />Click me for One Time Use Token protection</a><br />
<%}%>
<br />
<form method="POST" action="filter/SiteWideServlet?user=${user}">
	<csrf:forForm />
	<input type="submit">Submit Site-wide token protected Form</input>
</form>

<br />
<%if(ConfigUtil.isSessionMode()){ %>
<form method="POST" action="filter/OneTimeUseServlet?user=${user}">
	<csrf:forFormUrlSpecific url="/filter/OneTimeUseServlet" />
	<input type="submit">Submit One-time Use token protected Form</input>
</form>
<%}%>

<h2>AntiCSRF Custom Implementation Test Harness</h1>

<h2>AntiCSRF Filter Test Harness</h2>
<br />
<a href="custom/CustomSiteWideServlet?<csrf:forRequest />&user=${user}">Click me for site-wide token protected page</a><br />
<a href="custom/CustomURLSpecificServlet?<csrf:forRequestUrlSpecific url='/custom/CustomURLSpecificServlet' />&user=${user}" />Click me for URL Specific protection</a><br />
<%if(ConfigUtil.isSessionMode()){ %>
<a href="custom/CustomOneTimeUseServlet?<csrf:forRequestUrlSpecific url='/custom/CustomOneTimeUseServlet' />&user=${user}" />Click me for One Time Use Token protection</a><br />
<%}%>
<br />
<form method="POST" action="custom/CustomSiteWideServlet?user=${user}">
	<csrf:forForm />
	<input type="submit">Submit Site-wide token protected Form</input>
</form>

<br />
<%if(ConfigUtil.isSessionMode()){ %>
<form method="POST" action="custom/CustomOneTimeUseServlet?user-${user}">
	<csrf:forFormUrlSpecific url="/custom/CustomOneTimeUseServlet" />
	<input type="submit">Submit One-time Use token protected Form</input>
</form>
<%}%>
</html>