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


package com.gdssecurity.anticsrf.utils;

import java.util.List;

public class Config
{

	private String protectionMode;
	private String hmacKeyFile;
	private List<String> exemptURLs;
	private String tokenRequestAttribute;
	private String tokenParameterName;
	private Boolean monitorMode;
	private String errorMode;
	private String errorValue;
	
	
	Config() { };
	
	
	Config(
			String protectionMode,
			String hmacKeyFile,
			List<String> exemptURLs,
			String tokenRequestAttribute,
			String tokenParameterName,
			Boolean monitorMode,
			String errorMode,
			String errorValue)
	{
		this.protectionMode = protectionMode;
		this.hmacKeyFile = hmacKeyFile;
		this.exemptURLs = exemptURLs;
		this.tokenRequestAttribute = tokenRequestAttribute;
		this.tokenParameterName = tokenParameterName;
		this.monitorMode = monitorMode;
		this.errorMode = errorMode;
		this.errorValue = errorValue;
	}


	public String getProtectionMode() 
	{
		return protectionMode;
	}


	public String getHMACKeyFile() 
	{
		return hmacKeyFile;
	}


	public List<String> getExemptURLs() 
	{
		return exemptURLs;
	}


	public String getTokenRequestAttribute() 
	{
		return tokenRequestAttribute;
	}


	public String getTokenParameterName() 
	{
		return tokenParameterName;
	}


	public Boolean getMonitorMode() 
	{
		return monitorMode;
	}


	public String getErrorMode() 
	{
		return errorMode;
	}


	public String getErrorValue() 
	{
		return errorValue;
	}

}
