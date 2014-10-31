package com.gdssecurity.anticsrf.tags;

import java.util.logging.Logger;

import javax.servlet.jsp.tagext.BodyTagSupport;

import com.gdssecurity.anticsrf.utils.ConfigUtil;
import com.gdssecurity.anticsrf.utils.Constants;
import com.gdssecurity.anticsrf.utils.Encoder;

public class CSRFTokenParameterName extends BodyTagSupport {

	private static final long serialVersionUID = 6452788175106246620L;
	private static final Logger LOG = Logger.getLogger(CSRFTokenParameterName.class.getName());

	public int doStartTag()
	{
		try
		{
			String tokenParamName = ConfigUtil.getProp(Constants.CONF_TOKEN_PARAM);
			pageContext.getOut().print(Encoder.HtmlAttributeEncode(tokenParamName));
		}
		catch (Exception e)
		{
			e.printStackTrace();
			LOG.severe("Failed to write CSRF Token Parameter name taglib: exceptionmessage=" + e.getMessage());
		}
		return SKIP_BODY;
	}
}
