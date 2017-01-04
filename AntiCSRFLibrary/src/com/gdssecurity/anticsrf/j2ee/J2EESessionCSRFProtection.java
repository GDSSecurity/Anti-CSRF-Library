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


package com.gdssecurity.anticsrf.j2ee;

import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import com.gdssecurity.anticsrf.exceptions.CSRFTokenGenerationException;
import com.gdssecurity.anticsrf.exceptions.CSRFTokenVerificationException;
import com.gdssecurity.anticsrf.protections.SessionProtection;
import com.gdssecurity.anticsrf.utils.ConfigUtil;
import com.gdssecurity.anticsrf.utils.Constants;

public class J2EESessionCSRFProtection implements J2EECSRFProtection 
{
	private static final Logger LOG = Logger.getLogger(J2EESessionCSRFProtection.class.getName());

	private HttpServletRequest req;
	private J2EESession session;
	private SessionProtection protection;
	
	@Override
	public void setRequestObject(HttpServletRequest req) {
		this.req = req;
		this.session = new J2EESession(req.getSession());
		this.protection = new SessionProtection(session);
	}
	
	@Override
	public boolean verifyCSRFToken() throws CSRFTokenVerificationException
	{
		String url = req.getRequestURI();
		String tokenFromUser = req.getParameter( ConfigUtil.getProp(Constants.CONF_TOKEN_PARAM) );
		return this.protection.verifyCSRFToken(url, tokenFromUser); 
	}
	
	public String generateCSRFToken() throws CSRFTokenGenerationException
	{	
		String encodedCSRFToken = this.protection.generateCSRFToken();
		req.setAttribute(
				ConfigUtil.getProp(Constants.CONF_TOKEN_REQATTR), encodedCSRFToken);
		
		return encodedCSRFToken;
	}
	
	public String generateUrlSpecificCSRFToken(String url) 
	throws CSRFTokenGenerationException
	{	
		return this.protection.generateUrlSpecificCSRFToken(url);
	}
	
	public String getCSRFToken() 
	throws CSRFTokenGenerationException
	{
		String csrfToken = "";
		
		try
		{
			csrfToken = session.getAttribute( ConfigUtil.getProp((Constants.CONF_TOKEN_REQATTR))).toString();
			if( csrfToken == null)
			{
				csrfToken = generateCSRFToken();
			}
		}
		catch(NullPointerException ex)
		{
			csrfToken = generateCSRFToken();
		}
		
		return csrfToken;
	}
	
	public void setUserSeed(String userSeed)
	{
		LOG.warning("AntiCSRF Library is running on Session mode and a call to the unsupported setUsedSeed method was performed");
		return;
	}

	@Override
	public String getCSRFTokenParameterName() {
		return this.protection.getCSRFTokenParameterName();
	}
}
