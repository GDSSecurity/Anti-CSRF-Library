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
