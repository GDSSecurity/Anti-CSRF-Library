package com.gdssecurity.anticsrf.tags;

import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.jsp.tagext.BodyTagSupport;

import com.gdssecurity.anticsrf.j2ee.J2EECSRFProtection;
import com.gdssecurity.anticsrf.protections.CSRFProtection;
import com.gdssecurity.anticsrf.protections.CSRFProtectionFactory;
import com.gdssecurity.anticsrf.utils.ConfigUtil;
import com.gdssecurity.anticsrf.utils.Constants;

import org.owasp.encoder.*;

public class CSRFTokenUrlTag  extends BodyTagSupport
{
	private static final long serialVersionUID = 1L;
	private static final Logger LOG = Logger.getLogger(CSRFTokenUrlTag.class.getName());

	public int doStartTag()
	{
		try
		{
			HttpServletRequest req = (HttpServletRequest) pageContext.getRequest();
			
			J2EECSRFProtection csrfProtection = (J2EECSRFProtection)CSRFProtectionFactory.getCSRFProtection();
			csrfProtection.setRequestObject(req);
			String csrfToken = csrfProtection.getCSRFToken();
			String tokenParamName = ConfigUtil.getProp(Constants.CONF_TOKEN_PARAM);

			pageContext.getOut().print(Encode.forUriComponent(tokenParamName) +
					"=" + Encode.forUriComponent(csrfToken));
		}
		catch (Exception e)
		{
			e.printStackTrace();
			LOG.severe("Failed to write CSRF Token through taglib: exceptionmessage=" + e.getMessage());
		}
		
		return SKIP_BODY;
	}
	
}