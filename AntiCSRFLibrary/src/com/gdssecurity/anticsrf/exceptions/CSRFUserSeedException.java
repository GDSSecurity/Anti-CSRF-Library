package com.gdssecurity.anticsrf.exceptions;

import javax.servlet.ServletException;

public class CSRFUserSeedException extends ServletException
{
	private static final long serialVersionUID = 1L;
	
	String error;
	
	public CSRFUserSeedException()
	{
		super();
		error = "unknown";
	}
	
	public CSRFUserSeedException(String err)
	{
		super(err);
		error = err;
	}
	
	public CSRFUserSeedException(Exception e)
	{
		super(e);
		error = e.getMessage();
	}
	
	public String getError()
	{
		return error;
	} 
}
