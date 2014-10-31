package com.gdssecurity.anticsrf.j2ee;

import java.sql.Timestamp;
import java.util.Date;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import org.keyczar.Signer;
import org.keyczar.exceptions.KeyczarException;

import com.gdssecurity.anticsrf.exceptions.CSRFTokenGenerationException;
import com.gdssecurity.anticsrf.exceptions.CSRFTokenVerificationException;
import com.gdssecurity.anticsrf.protections.HMACCSRFProtection;
import com.gdssecurity.anticsrf.utils.ConfigUtil;
import com.gdssecurity.anticsrf.utils.Constants;
import com.gdssecurity.anticsrf.utils.Encoder;
import com.gdssecurity.anticsrf.utils.KeyczarWrapper;

public class J2EEHmacCSRFProtection implements J2EECSRFProtection
{
	private static final Logger LOG = Logger.getLogger(J2EEHmacCSRFProtection.class.getName());
	
	private HttpServletRequest req;
	private HMACCSRFProtection protection;
	
	@Override
	public void setRequestObject(HttpServletRequest req) {
		this.req = req;
		this.protection = new HMACCSRFProtection(getUserSeed());
	}
	
	
	/*
	 * Additional verification method for URL-specific tokens for a specified token max-age/timeout.
	 */
	/*
	public boolean verifyUrlSpecificCSRFToken(String token, Integer tokenTimeoutSecs) throws CSRFTokenVerificationException
	{
		return verifyCSRFToken(token, true, (tokenTimeoutSecs != null ? new Long(tokenTimeoutSecs) : null));
	}*/

	public boolean verifyCSRFToken() throws CSRFTokenVerificationException
	{
		// Get CSRF Token from configured request parameter
		String submittedCSRFToken = req.getParameter(
				ConfigUtil.getProp(Constants.CONF_TOKEN_PARAM) );
		return this.protection.verifyCSRFToken(req.getRequestURI(), submittedCSRFToken);
	}
	
	public String generateCSRFToken() throws CSRFTokenGenerationException
	{
		String csrfToken = this.protection.generateCSRFToken();
		
		req.setAttribute( ConfigUtil.getProp(Constants.CONF_TOKEN_REQATTR), csrfToken );
		
		return csrfToken;
	}
	
	public String generateUrlSpecificCSRFToken(String url) throws CSRFTokenGenerationException
	{
		return this.protection.generateUrlSpecificCSRFToken(url);
	}
	
	public String getCSRFToken() throws CSRFTokenGenerationException
	{
		String csrfToken = "";
		
		try
		{
			csrfToken =  req.getAttribute(ConfigUtil.getProp(Constants.CONF_TOKEN_REQATTR)).toString();
			if(csrfToken == null)
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
		req.setAttribute(ConfigUtil.getProp(Constants.CONF_HMAC_USERSEED_ATTR), userSeed);
	}

	@Override
	public String getCSRFTokenParameterName() {
		return this.protection.getCSRFTokenParameterName();
	}
	
	protected String getUserSeed()
	{
		String userSeed = (String) req.getAttribute(
				ConfigUtil.getProp(Constants.CONF_HMAC_USERSEED_ATTR) );
		
		if( userSeed == null )
		{
			String err = "User Seed not found in HttpServletRequest attribute. " 
					+ "Defaulting to an generic user seed since we cannot tie the token to a user identity";
			LOG.warning(err);
			return "anonymous";
		}
		
		return userSeed;
	}
}
