package com.gdssecurity.anticsrf.utils;

import java.util.List;

public class ConfigBuilder
{
	
	private String protectionMode;
	private String hmacKeyFile;
	private List<String> exemptURLs;
	private String tokenRequestAttribute;
	private String tokenParameterName;
	private Boolean monitorMode;
	private String errorMode;
	private String errorValue;
	
	
	public ConfigBuilder() { }


	public String getProtectionMode() 
	{
		return protectionMode;
	}


	public ConfigBuilder setProtectionMode(String protectionMode) 
	{
		this.protectionMode = protectionMode;
		return this;
	}


	public String getHMACKeyFile() 
	{
		return hmacKeyFile;
	}


	public ConfigBuilder setHMACKeyFile(String hmacKeyFile) 
	{
		this.hmacKeyFile = hmacKeyFile;
		return this;
	}


	public List<String> getExemptURLs() 
	{
		return exemptURLs;
	}


	public ConfigBuilder setExemptURLs(List<String> exemptURLs) 
	{
		this.exemptURLs = exemptURLs;
		return this;
	}


	public String getTokenRequestAttribute() 
	{
		return tokenRequestAttribute;
	}


	public ConfigBuilder setTokenRequestAttribute(String tokenRequestAttribute) 
	{
		this.tokenRequestAttribute = tokenRequestAttribute;
		return this;
	}


	public String getTokenParameterName() 
	{
		return tokenParameterName;
	}


	public ConfigBuilder setTokenParameterName(String tokenParameterName) 
	{
		this.tokenParameterName = tokenParameterName;
		return this;
	}


	public Boolean getMonitorMode() 
	{
		return monitorMode;
	}


	public ConfigBuilder setMonitorMode(Boolean monitorMode) 
	{
		this.monitorMode = monitorMode;
		return this;
	}


	public String getErrorMode() 
	{
		return errorMode;
	}


	public ConfigBuilder setErrorMode(String errorMode) 
	{
		this.errorMode = errorMode;
		return this;
	}


	public String getErrorValue() 
	{
		return errorValue;
	}


	public ConfigBuilder setErrorValue(String errorValue) 
	{
		this.errorValue = errorValue;
		return this;
	}
	
	
	public Config getConfig()
	{
		return new Config(
			protectionMode,
			hmacKeyFile,
			exemptURLs,
			tokenRequestAttribute,
			tokenParameterName,
			monitorMode,
			errorMode,
			errorValue);
	}
	
}
