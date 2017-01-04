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


package com.sendsafely.testapp.filters;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.gdssecurity.anticsrf.j2ee.J2EECSRFProtection;
import com.gdssecurity.anticsrf.protections.CSRFProtection;
import com.gdssecurity.anticsrf.protections.CSRFProtectionFactory;
import com.gdssecurity.anticsrf.utils.ConfigUtil;
import com.gdssecurity.anticsrf.utils.Constants;
import com.sendsafely.testapp.servlets.CustomOneTimeUseServlet;

/**
 * Servlet Filter implementation class customcsrffilter
 */
public class CustomCSRFFilter implements Filter 
{
	private static final Logger LOG = Logger.getLogger(CustomCSRFFilter.class.getName());
	FilterConfig filterConfig = null;

    public CustomCSRFFilter() {

    }

	public void destroy()
	{
		filterConfig = null;
	}


	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException 
	{
		J2EECSRFProtection csrfProtection = CSRFProtectionFactory.getCSRFProtection();
		csrfProtection.setRequestObject((HttpServletRequest)request);
		if( !csrfProtection.verifyCSRFToken() )
		{
			LOG.info("CSRF Verification Failed");
			HttpServletResponse res = (HttpServletResponse)response;
			res.sendError(403);
			return;
		}
		
		// pass the request along the filter chain
		chain.doFilter(request, response);
	}

	public void init(FilterConfig fConfig) throws ServletException 
	{
        // Check to see if an init param has been set
        String configFile  = fConfig.getInitParameter(Constants.CONF_INITPARAMNAME);
        
        if(configFile == null)
        {
        	configFile = fConfig.getServletContext().getRealPath("") + Constants.FILE_SEPARATOR + 
        			Constants.WEB_CONTAINER + Constants.FILE_SEPARATOR + Constants.CONFIGNAME;
        	LOG.info("No Filter init-param set, defaulting to loading AntiCSRF Configuration from "+configFile);
        }
        else
        {
        	LOG.info("AntiCSRF Configuration init-param specified. Configuration file set to "+configFile);
        }
        
        ConfigUtil.loadConfig(configFile);
		this.filterConfig = fConfig;   
	}

}
