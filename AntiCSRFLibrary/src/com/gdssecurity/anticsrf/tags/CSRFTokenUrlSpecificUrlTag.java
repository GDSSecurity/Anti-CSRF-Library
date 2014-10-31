package com.gdssecurity.anticsrf.tags;

import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.jsp.tagext.BodyTagSupport;

import com.gdssecurity.anticsrf.j2ee.J2EECSRFProtection;
import com.gdssecurity.anticsrf.protections.CSRFProtection;
import com.gdssecurity.anticsrf.protections.CSRFProtectionFactory;
import com.gdssecurity.anticsrf.utils.ConfigUtil;
import com.gdssecurity.anticsrf.utils.Constants;
import com.gdssecurity.anticsrf.utils.Encoder;

public class CSRFTokenUrlSpecificUrlTag extends BodyTagSupport
{
	private static final long serialVersionUID = 1L;
	private static final Logger LOG = Logger.getLogger(CSRFTokenUrlSpecificUrlTag.class.getName());
	
	protected String url = null;
	
	public String getUrl()
	{
		
		return(this.url);
	}
	
	public void setUrl(String url)
	{
		this.url = url;
	}
	
	public int doStartTag()
	{
		try
		{
			HttpServletRequest req = (HttpServletRequest) pageContext.getRequest();
			
			J2EECSRFProtection csrfProtection = (J2EECSRFProtection)CSRFProtectionFactory.getCSRFProtection();
			csrfProtection.setRequestObject(req);
			String csrfToken = csrfProtection.generateUrlSpecificCSRFToken(this.url);
			String tokenParamName = ConfigUtil.getProp(Constants.CONF_TOKEN_PARAM);

			pageContext.getOut().print(Encoder.UrlEncode(tokenParamName) + 
					"=" + Encoder.UrlEncode(csrfToken));
		}
		catch (Exception e)
		{
			LOG.severe("Failed to write CSRF Token through taglib: exceptionmessage=" + e.getMessage());
		}
		
		return SKIP_BODY;
	}
	
}
