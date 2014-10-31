package com.gdssecurity.anticsrf.exceptions;

import javax.servlet.ServletException;

public class CSRFTokenGenerationException extends ServletException 
{
	private static final long serialVersionUID = 1L;
	
	String error;
	
	public CSRFTokenGenerationException()
	{
		super();
		error = "unknown";
	}
	
	public CSRFTokenGenerationException(String err)
	{
		super(err);
		error = err;
	}
	
	public CSRFTokenGenerationException(Exception e)
	{
		super(e);
		error = e.getMessage();
	}
	
	public String getError()
	{
		return error;
	}
}
