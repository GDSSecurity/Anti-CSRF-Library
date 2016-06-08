package com.gdssecurity.anticsrf.tags;

import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.jsp.tagext.BodyTagSupport;

import com.gdssecurity.anticsrf.j2ee.J2EECSRFProtection;
import com.gdssecurity.anticsrf.protections.CSRFProtection;
import com.gdssecurity.anticsrf.protections.CSRFProtectionFactory;

import org.owasp.encoder.*;

public class CSRFToken extends BodyTagSupport {

	private static final long serialVersionUID = -8218630240154573675L;

	private static final Logger LOG = Logger.getLogger(CSRFTokenFormTag.class.getName());

	public int doStartTag()
	{
		try
		{
			HttpServletRequest req = (HttpServletRequest) pageContext.getRequest();
			J2EECSRFProtection csrfProtection = (J2EECSRFProtection)CSRFProtectionFactory.getCSRFProtection();
			csrfProtection.setRequestObject(req);
			String csrfToken = csrfProtection.getCSRFToken();
			
			pageContext.getOut().print(Encode.forHtmlAttribute(csrfToken));
		}
		catch (Exception e)
		{
			e.printStackTrace();
			LOG.severe("Failed to write CSRF Token through taglib: exceptionmessage=" + e.getMessage());
		}
		return SKIP_BODY;
	}
	
}
