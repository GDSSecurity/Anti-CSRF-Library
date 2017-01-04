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
