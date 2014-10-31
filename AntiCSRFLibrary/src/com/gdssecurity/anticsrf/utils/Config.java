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
