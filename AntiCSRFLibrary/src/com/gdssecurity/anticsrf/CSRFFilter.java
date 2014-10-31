package com.gdssecurity.anticsrf;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.gdssecurity.anticsrf.exceptions.CSRFTokenVerificationException;
import com.gdssecurity.anticsrf.j2ee.J2EECSRFProtection;
import com.gdssecurity.anticsrf.j2ee.J2EEHmacCSRFProtection;
import com.gdssecurity.anticsrf.protections.CSRFProtection;
import com.gdssecurity.anticsrf.protections.CSRFProtectionFactory;
import com.gdssecurity.anticsrf.utils.ConfigUtil;
import com.gdssecurity.anticsrf.utils.Constants;
import com.gdssecurity.anticsrf.utils.Encoder;

public class CSRFFilter implements Filter 
{
	private static final Logger LOG = Logger.getLogger(CSRFFilter.class.getName());
	FilterConfig filterConfig;

	/*
	 * (non-Javadoc)
	 * @see javax.servlet.Filter#destroy()
	 */
	public void destroy(){}

	public void init(final FilterConfig filterConfig) throws ServletException 
	{
        LOG.info("The CSRFFilter is inititializing");
        
        // Check to see if an init param has been set
        String configFile  = filterConfig.getInitParameter(Constants.CONF_INITPARAMNAME);
        
        if(configFile == null)
        {
        	configFile = "/WEB-INF/" + Constants.CONFIGNAME;
        	LOG.info("No Filter init-param set, defaulting to loading AntiCSRF Configuration from "+configFile);
        }
        else
        {
        	LOG.info("AntiCSRF Configuration init-param specified. Configuration file set to "+configFile);
        }
        
        InputStream inputStream = filterConfig.getServletContext().getResourceAsStream(configFile);
        ConfigUtil.loadConfig(inputStream);
        this.filterConfig = filterConfig;
	}

	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws ServletException, IOException 
	{
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		
		LOG.fine("The CSRFFilter is running on URL: " + Encoder.stripNewlines(req.getRequestURI()) );
		
		// If Hmac mode, lets add a new token to the request attribute first
		// This will allow for a rolling timestamp on the CSRFToken
		
		// If Session, the token will be valid across the whole life of the
		// session token. Therefore, we will only generate a new one if a Token
		// is not currently set within session.
		
		J2EECSRFProtection csrfProtection = (J2EECSRFProtection)CSRFProtectionFactory.getCSRFProtection();
		csrfProtection.setRequestObject(req);
		
		if(ConfigUtil.isHmacMode())
		{
			csrfProtection.generateCSRFToken();
		}
		else
		{
			HttpSession session = req.getSession(true);
			String storedCSRFToken = (String) session.getAttribute(
					ConfigUtil.getProp(Constants.CONF_TOKEN_REQATTR));
			
			if(storedCSRFToken == null || storedCSRFToken.equals(""))	
			{
				csrfProtection.generateCSRFToken();
			}
			else
			{
				req.setAttribute(
					ConfigUtil.getProp(Constants.CONF_TOKEN_REQATTR), storedCSRFToken);
			}
		}
		
		try
		{
			if( !csrfProtection.verifyCSRFToken() )
			{
				String err = "User submitted an invalid CSRFToken.";
				LOG.warning(err+", submittedToken=" + Encoder.stripNewlines(req.getParameter(
								ConfigUtil.getProp(Constants.CONF_TOKEN_PARAM))) );
				throw new CSRFTokenVerificationException(err);
			}
		}
		catch( CSRFTokenVerificationException ex )
		{
			// If MonitorMode is disabled, we handle the invalid CSRF Token validation error
			// If not, we continue normal execution.
			if(ConfigUtil.getProp(Constants.CONF_MONITORMODE).equals("no"))
			{
				handleError(req, res);
				return;
			}
			
		}
		
		chain.doFilter(request, response);
	}
	
	private void handleError(HttpServletRequest req, HttpServletResponse res) 
			throws IOException, ServletException
	{
		// Check if the request is an XMLHTTPRequest/AJAX request
		if(ConfigUtil.getProp(Constants.CONF_ERROR_AJAX) != null)
		{
			if(req.getHeader("X-Requested-With") != null && 
					req.getHeader("X-Requested-With").equals("XMLHttpRequest") )
			{
				res.setContentType("application/json");
				res.getWriter().write("{\"error\":{\"type\":\"invalid_csrf\"}");
				return;
			}
		}
		
		// Token validation failed. Lets handle the error based on the config file
		if( ConfigUtil.getProp(Constants.CONF_ERROR).equals("redirect") )
		{
			res.sendRedirect(ConfigUtil.getProp(Constants.CONF_ERRORVAL));
		}
		else if( ConfigUtil.getProp(Constants.CONF_ERROR).equals("forward") )
		{
			String forwardUrl = ConfigUtil.getProp(Constants.CONF_ERRORVAL);
			RequestDispatcher dispatcher = req.getRequestDispatcher(forwardUrl);
			dispatcher.forward(req, res);
		}
		else if( ConfigUtil.getProp(Constants.CONF_ERROR).equals("status_code"))
		{
			int statusCode = Integer.parseInt(ConfigUtil.getProp(Constants.CONF_ERRORVAL));
			res.sendError(statusCode, "CSRF Token validation failed");
		}
		else
		{
			// No configuration.. so lets just send them our own error
			res.sendError(403, "CSRF Token validation failed");
		}
	}
}
