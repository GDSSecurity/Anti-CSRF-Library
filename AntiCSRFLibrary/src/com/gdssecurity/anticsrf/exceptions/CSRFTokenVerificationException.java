package com.gdssecurity.anticsrf.exceptions;

import javax.servlet.ServletException;

public class CSRFTokenVerificationException extends ServletException
{
	private static final long serialVersionUID = 1L;
	
	String error;
	
	public CSRFTokenVerificationException()
	{
		super();
		error = "unknown";
	}
	
	public CSRFTokenVerificationException(String err)
	{
		super(err);
		error = err;
	}
	
	public CSRFTokenVerificationException(Exception e)
	{
		super(e);
		error = e.getMessage();
	}
	
	public String getError()
	{
		return error;
	} 
}
