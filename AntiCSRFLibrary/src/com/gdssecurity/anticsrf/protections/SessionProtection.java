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


package com.gdssecurity.anticsrf.protections;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.logging.Logger;

import com.gdssecurity.anticsrf.exceptions.CSRFTokenGenerationException;
import com.gdssecurity.anticsrf.exceptions.CSRFTokenVerificationException;
import com.gdssecurity.anticsrf.utils.Base64;
import com.gdssecurity.anticsrf.utils.ConfigUtil;
import com.gdssecurity.anticsrf.utils.Constants;
import com.gdssecurity.anticsrf.utils.StringUtil;
import com.gdssecurity.anticsrf.utils.SecureCompare;

public class SessionProtection implements CSRFProtection {
	
	private static final Logger LOG = Logger.getLogger(SessionProtection.class.getName());
	
	SesssionInterface session;
	
	public SessionProtection(SesssionInterface session)
	{
		this.session = session;
	}

	@Override
	public boolean verifyCSRFToken(String url, String tokenFromUser)
			throws CSRFTokenVerificationException {
		if( ConfigUtil.hasOneTimeUseConfig(url) )
		{
			return verifyOneTimeUseCSRFToken(url, tokenFromUser);
		}
		
		return verifyCSRFToken(url, tokenFromUser, ConfigUtil.hasUrlSpecificConfig(url));
	}

	@Override
	public String generateCSRFToken() throws CSRFTokenGenerationException {
		String encodedCSRFToken = generateRandomToken();	
		LOG.fine("Setting CSRFToken into Session: StoredToken="+encodedCSRFToken);
		
		session.setAttribute(
				ConfigUtil.getProp(Constants.CONF_TOKEN_REQATTR), encodedCSRFToken);
		
		return encodedCSRFToken;
	}

	@Override
	public String getCSRFTokenParameterName() {
		return ConfigUtil.getProp(Constants.CONF_TOKEN_PARAM);
	}

	@Override
	public String generateUrlSpecificCSRFToken(String url) throws CSRFTokenGenerationException {
		@SuppressWarnings("unchecked")
		HashMap<String,String> urlSpecificTokens = 
			(HashMap<String,String>) session.getAttribute(
				ConfigUtil.getProp(Constants.CONF_TOKEN_REQATTR)+"urlspecific");
		
		// If URLSpecificToken Map is not in session, lets create one and add
		if(urlSpecificTokens == null)
		{
			urlSpecificTokens = new HashMap<String,String>();
			session.setAttribute(
				ConfigUtil.getProp(
					Constants.CONF_TOKEN_REQATTR)+"urlspecific", urlSpecificTokens);
		}
		
		// Only set a new token if one does not already exist
		if(!urlSpecificTokens.containsKey(url))
		{
			String encodedCSRFToken = generateRandomToken();
			LOG.fine("Setting a new url specific token. url=" + StringUtil.stripNewlines(url)
					+", newToken=" + encodedCSRFToken);
			urlSpecificTokens.put(url, encodedCSRFToken);
		}
		else
		{
			LOG.fine("URL Specific Mapping already exists. using existing value");
		}
		
		return urlSpecificTokens.get(url);
	}
	
	// One-time use tokens will be UrlSpecific Tokens which are removed
	// from session upon validation.
	public boolean verifyOneTimeUseCSRFToken(String url, String tokenFromUser) throws CSRFTokenVerificationException
	{
		boolean isValidToken = verifyCSRFToken(url, tokenFromUser, true);
		
		@SuppressWarnings("unchecked")
		HashMap<String,String> urlSpecificTokens = 
			(HashMap<String,String>) session.getAttribute(
				ConfigUtil.getProp(Constants.CONF_TOKEN_REQATTR)+"urlspecific");
		
		if(urlSpecificTokens != null)
		{
			urlSpecificTokens.remove(url);
		}
		
		return isValidToken;
	}
	
	private boolean verifyCSRFToken(String url, String tokenFromUser, boolean isUrlSpecific) throws CSRFTokenVerificationException
	{
		if( ConfigUtil.isURLExempt(url) )
		{
			return true;
		}

		String storedCSRFToken = (String) session.getAttribute(
				ConfigUtil.getProp(Constants.CONF_TOKEN_REQATTR) );
		
		if(isUrlSpecific)
		{
			LOG.fine("About to perform urlspecific CSRF Token verification");
			
			@SuppressWarnings("unchecked")
			HashMap<String,String> urlSpecificTokens = 
					(HashMap<String,String>) session.getAttribute(
						ConfigUtil.getProp(Constants.CONF_TOKEN_REQATTR)+"urlspecific");		
			try
			{
				storedCSRFToken = urlSpecificTokens.get(url);
				LOG.fine("Reading URL Specific Token prior to verification: tokenread="+StringUtil.stripNewlines(storedCSRFToken));
				if(storedCSRFToken == null)
				{
					return false;
				}
			}
			catch(NullPointerException ex)
			{
				String err = "No URL Specific Token found. URL="+StringUtil.stripNewlines(url);
				LOG.warning(err);
				return false;
			}
			
		}
		
		return handleCSRFTokenVerification(tokenFromUser, storedCSRFToken);
	}
	
	private boolean handleCSRFTokenVerification(String tokenFromUser, String storedCSRFToken) throws CSRFTokenVerificationException
	{	
		LOG.fine("About to compare: submittedToken="+StringUtil.stripNewlines(tokenFromUser) +
				", storedToken="+storedCSRFToken);
		
		if( tokenFromUser != null && storedCSRFToken != null )
		{
			// SecureCompare validates the entire string and is therefore not susceptible to timing attacks
			if(SecureCompare.isEqual(tokenFromUser.getBytes(), storedCSRFToken.getBytes()))
			{
				return true;
			}
			
			LOG.warning("Failed to validate user's csrfToken: submittedToken=" + 
					StringUtil.stripNewlines(tokenFromUser) + ", expectedToken="+storedCSRFToken);
		}
		
		return false;
	}
	
	private String generateRandomToken() throws CSRFTokenGenerationException
	{
		SecureRandom sr;
		
		try 
		{
			sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
		}
		catch (NoSuchAlgorithmException e)
		{
			String err = "Failed to generate CSRFToken using SecureRandom"
					+ ", exceptionMessage=" + e.getMessage();
			LOG.severe(err);
			throw new CSRFTokenGenerationException(err + ", exceptionMessage="
					+ e.getMessage());
		
		}
		catch (NoSuchProviderException e)
		{
			// Let's try and get the preferred one if SUN doesn't exist.
			try 
			{
				sr = SecureRandom.getInstance("SHA1PRNG");
			} 
			catch (NoSuchAlgorithmException e1) {
				String err = "Failed to generate CSRFToken using SecureRandom"
						+ ", exceptionMessage=" + e1.getMessage();
				LOG.severe(err);
				throw new CSRFTokenGenerationException(err + ", exceptionMessage="
						+ e1.getMessage());
			}
		}
		
		byte[] randomBytes = new byte[32];
		sr.nextBytes(randomBytes);			
		return Base64.encode(randomBytes);
	}

}
