/*
 * Copyright 2014-2016 Gotham Digital Science LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package com.gdssecurity.anticsrf.tags;

import java.util.logging.Logger;

import javax.servlet.jsp.tagext.BodyTagSupport;

import com.gdssecurity.anticsrf.utils.ConfigUtil;
import com.gdssecurity.anticsrf.utils.Constants;

import org.owasp.encoder.*;

public class CSRFTokenParameterName extends BodyTagSupport {

	private static final long serialVersionUID = 6452788175106246620L;
	private static final Logger LOG = Logger.getLogger(CSRFTokenParameterName.class.getName());

	public int doStartTag()
	{
		try
		{
			String tokenParamName = ConfigUtil.getProp(Constants.CONF_TOKEN_PARAM);
			pageContext.getOut().print(Encode.forHtmlAttribute(tokenParamName));
		}
		catch (Exception e)
		{
			e.printStackTrace();
			LOG.severe("Failed to write CSRF Token Parameter name taglib: exceptionmessage=" + e.getMessage());
		}
		return SKIP_BODY;
	}
}
