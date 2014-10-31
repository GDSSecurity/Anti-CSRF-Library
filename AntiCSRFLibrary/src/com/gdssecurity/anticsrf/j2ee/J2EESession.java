package com.gdssecurity.anticsrf.j2ee;

import javax.servlet.http.HttpSession;

import com.gdssecurity.anticsrf.protections.SesssionInterface;

public class J2EESession implements SesssionInterface {

	private HttpSession session;
	
	public J2EESession(HttpSession session)
	{
		this.session = session;
	}
	
	@Override
	public Object getAttribute(String key) {
		return this.session.getAttribute(key);
	}

	@Override
	public void setAttribute(String key, Object obj) {
		session.setAttribute(key, obj);
	}

	
	
}
