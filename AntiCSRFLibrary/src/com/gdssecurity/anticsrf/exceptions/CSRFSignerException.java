package com.gdssecurity.anticsrf.exceptions;

import javax.servlet.ServletException;

public class CSRFSignerException extends ServletException
{
	private static final long serialVersionUID = 1L;
	
	String error;
	
	public CSRFSignerException()
	{
		super();
		error = "unknown";
	}
	
	public CSRFSignerException(String err)
	{
		super(err);
		error = err;
	}
	
	public CSRFSignerException(Exception e)
	{
		super(e);
		error = e.getMessage();
	}
	
	public String getError()
	{
		return error;
	}
}
