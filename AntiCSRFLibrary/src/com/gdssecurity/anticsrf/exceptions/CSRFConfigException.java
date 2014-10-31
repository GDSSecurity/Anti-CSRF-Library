package com.gdssecurity.anticsrf.exceptions;

import javax.servlet.ServletException;

public class CSRFConfigException extends ServletException
{
	private static final long serialVersionUID = 1L;
	
	String error;
	
	public CSRFConfigException()
	{
		super();
		error = "unknown";
	}
	
	public CSRFConfigException(String err)
	{
		super(err);
		error = err;
	}
	
	public CSRFConfigException(Exception e)
	{
		super(e);
		error = e.getMessage();
	}
	
	public String getError()
	{
		return error;
	}
}
