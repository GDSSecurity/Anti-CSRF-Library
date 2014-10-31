package com.gdssecurity.anticsrf.protections;

public interface SesssionInterface {

	public Object getAttribute(String key);
	public void setAttribute(String key, Object obj);
	
}
