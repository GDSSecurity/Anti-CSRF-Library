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


package com.sendsafely.testapp.servlets;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.gdssecurity.anticsrf.protections.CSRFProtection;
import com.gdssecurity.anticsrf.protections.CSRFProtectionFactory;

public class CustomOneTimeUseServlet extends HttpServlet 
{
	private static final long serialVersionUID = 1L;
	private static final Logger LOG = Logger.getLogger(CustomOneTimeUseServlet.class.getName());

    public CustomOneTimeUseServlet() 
    {
        super();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) 
	throws ServletException, IOException 
	{
		LOG.info("One Time Use Servlet with Custom Impl Hit");	
		request.getRequestDispatcher("/onetimeuse.jsp").forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) 
	throws ServletException, IOException 
	{
		doGet(request, response);
	}
	
}
