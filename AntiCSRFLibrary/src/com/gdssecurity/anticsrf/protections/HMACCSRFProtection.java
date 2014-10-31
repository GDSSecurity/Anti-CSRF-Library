package com.gdssecurity.anticsrf.protections;

import java.sql.Timestamp;
import java.util.Date;
import java.util.logging.Logger;

import org.keyczar.Signer;
import org.keyczar.exceptions.KeyczarException;

import com.gdssecurity.anticsrf.exceptions.CSRFTokenGenerationException;
import com.gdssecurity.anticsrf.exceptions.CSRFTokenVerificationException;
import com.gdssecurity.anticsrf.utils.ConfigUtil;
import com.gdssecurity.anticsrf.utils.Constants;
import com.gdssecurity.anticsrf.utils.Encoder;
import com.gdssecurity.anticsrf.utils.KeyczarWrapper;

public class HMACCSRFProtection implements CSRFProtection {

	private static final Logger LOG = Logger.getLogger(HMACCSRFProtection.class.getName());
	
	private String userSeed;
	
	public HMACCSRFProtection(String userSeed) 
	{
		this.userSeed = userSeed;
	}
	
	@Override
	public boolean verifyCSRFToken(String url, String tokenFromUser) throws CSRFTokenVerificationException {
		return verifyCSRFToken(url, tokenFromUser, ConfigUtil.hasUrlSpecificConfig(url));
	}

	@Override
	public String generateCSRFToken() throws CSRFTokenGenerationException {
		String csrfToken = handleCSRFTokenGeneration(this.userSeed);
		
		LOG.fine("Setting csrfToken: attrname=" + 
				ConfigUtil.getProp(Constants.CONF_TOKEN_REQATTR) +
				", csrftoken=" + csrfToken);
		return csrfToken;
	}

	@Override
	public String getCSRFTokenParameterName() {
		return ConfigUtil.getProp(Constants.CONF_TOKEN_PARAM);
	}

	@Override
	public String generateUrlSpecificCSRFToken(String url)
			throws CSRFTokenGenerationException {
		return this.generateCSRFToken(userSeed+":"+url);
	}
	
	private String generateCSRFToken(String userSeed) throws CSRFTokenGenerationException {
		String csrfToken = handleCSRFTokenGeneration(userSeed);
		
		LOG.info("Setting csrfToken: attrname=" + 
				ConfigUtil.getProp(Constants.CONF_TOKEN_REQATTR) +
				", csrftoken=" + csrfToken);
		return csrfToken;
	}
	
	private boolean verifyCSRFToken(String url, String token, boolean isUrlSpecific, Long timeout) throws CSRFTokenVerificationException
	{
		// Get  CSRF User Seed from request attribute and set the default timeout
		StringBuffer userSeed = new StringBuffer(this.userSeed);
		
		if(isUrlSpecific)
		{
			// Add the current url to the seed and pass in it's configured timeout
			userSeed.append( ":" + url );
			LOG.fine("Using URL Specific timeout values");
		}
		
		return handleCSRFTokenVerification(url, token, userSeed.toString(), timeout);
	}
	
	private boolean handleCSRFTokenVerification(String url, String submittedCSRFToken, String userSeed, Long configuredTimeout ) throws CSRFTokenVerificationException
	{
		if( ConfigUtil.isURLExempt( url ) )
		{
			return true;
		}
		
		try 
		{
			if( submittedCSRFToken == null)
			{
				String err = "HttpServletRequest is missing CSRFToken Parameter." +
							"userSeed=" + Encoder.stripNewlines(userSeed);
				LOG.warning(err);
				return false;
			}
			
			String[] csrfTokenContents = submittedCSRFToken.split(":");
	
			if( csrfTokenContents.length != 2 ) 
			{
				LOG.warning("CSRF Token contains invalid amount of delimiters. "+
						"userSeed=" + Encoder.stripNewlines(userSeed) + 
						", submittedToken= " + Encoder.stripNewlines(submittedCSRFToken));
				return false;
			}
			
			String submittedHmac = csrfTokenContents[0];
			String submittedTimestamp = csrfTokenContents[1];
			
			// Get Keyczar Signer object
			KeyczarWrapper keyczarWrapper = ConfigUtil.getKeyczarWrapper();
			Signer csrfSigner = keyczarWrapper.getCSRFSigner();
			
			if( !csrfSigner.verify(userSeed + ":" + submittedTimestamp, submittedHmac) )
			{
				LOG.warning("Submitted CSRF Token did not contain a valid HMAC signature. "+
						"userSeed=" + Encoder.stripNewlines(userSeed) + 
						", submittedToken=" + Encoder.stripNewlines(submittedCSRFToken));
				return false;
			}
			
			if( timestampIsExpired( Long.valueOf(submittedTimestamp), configuredTimeout) )
			{
				LOG.warning("Submitted CSRF Token is expired. "+
						"userSeed=" + Encoder.stripNewlines(userSeed) + 
						", submittedToken= " + Encoder.stripNewlines(submittedCSRFToken));
				return false;
			}
			
			// We passed all the checks.
			return true;
		} 
		catch( KeyczarException ex ) 
		{
			String err = "Encountered error performing HMAC signature validation with the Keyczar library";
					
			// Logging a warning here since this exception is caught and handled by the filter. This should
			// should be considered a security warning. 
			LOG.warning(err+ ", userSeed=" + Encoder.stripNewlines(userSeed) + 
					", submittedToken=" + Encoder.stripNewlines(submittedCSRFToken) + 
					", exception=" + ex.getMessage() );
			throw new CSRFTokenVerificationException(err);
		}
		catch( NumberFormatException ex )
		{
			String err = "Timestamp submitted within CSRFToken is not in a valid format";

			LOG.warning(err + ", Submitted CSRFToken="+
					submittedCSRFToken + ", userSeed=" + userSeed);
			throw new CSRFTokenVerificationException(err);
		}
	}
	
	private boolean timestampIsExpired( Long submittedTimestamp, Long configuredTimeout )
	{
		try 
		{
			Date current = new Date();

			Timestamp currentTime = new Timestamp( current.getTime() );
			Timestamp timeToCompare = new Timestamp(submittedTimestamp);

			Long diff = currentTime.getTime() - timeToCompare.getTime();
			Long diffInSeconds = diff / 1000; // 1,000 MilliSecs in a second 
			
			if (diffInSeconds > configuredTimeout) 
			{
				return true;
			}
		} 
		catch (Exception e) 
		{
			//log severe?
			LOG.severe("Unexpected error occurred during CSRFToken timestamp verification, " +
					"exceptionmessage=" + e.getMessage());
			return true;
		}
		
		return false;
	}
	
	private boolean verifyCSRFToken(String url, String tokenFromUser, boolean isUrlSpecific) throws CSRFTokenVerificationException
	{
		Long timeout = (isUrlSpecific 
				? ConfigUtil.getUrlSpecificConfig(url) 
				: Long.valueOf( ConfigUtil.getProp(Constants.CONF_HMAC_SITEWIDE_TIMEOUT) ));
		
		return verifyCSRFToken(url, tokenFromUser, isUrlSpecific, timeout);
	}
	
	private String handleCSRFTokenGeneration(String unhashedToken) throws CSRFTokenGenerationException
	{
		try
		{			
			Date currentTime = new Date();
			String currentTimeString = String.valueOf( currentTime.getTime() );
			KeyczarWrapper keyczarWrapper = ConfigUtil.getKeyczarWrapper();
			Signer csrfSigner = keyczarWrapper.getCSRFSigner();
			String csrfHmac = csrfSigner.sign(unhashedToken + ":" + currentTimeString);
			
			return csrfHmac + ":" + currentTimeString;
		}
		catch( KeyczarException ex ) 
		{
			String err = "Encountered error creating HMAC signature with the Keyczar library"
					+ ", exceptionmessage=" + ex.getMessage();
			LOG.info(err);
			throw new CSRFTokenGenerationException(err);
		}
	}

}
