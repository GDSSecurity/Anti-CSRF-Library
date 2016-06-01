package com.sendsafely.testapp.servlets;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Logger;


import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.encoder.*;

/**
 * Servlet implementation class HomeServlet
 */
public class HomeServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static final Logger LOG = Logger.getLogger(HomeServlet.class.getName());
  
    /**
     * @see HttpServlet#HttpServlet()
     */
    public HomeServlet() 
    {
        super();
    	LOG.info("Running HomeServlet Constructor");

    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    	LOG.info("Running HomeServlet doGet");
		if(request.getParameter("user") != null)
		{
			request.setAttribute("user", Encode.forHtmlAttribute(Encode.forUriComponent((request.getParameter("user")))));
		}
		request.getRequestDispatcher("/Home.jsp").forward(request, response);
	}


	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}

}
