package com.gdssecurity.anticsrf.j2ee;

import javax.servlet.http.HttpServletRequest;

import com.gdssecurity.anticsrf.exceptions.CSRFTokenGenerationException;
import com.gdssecurity.anticsrf.exceptions.CSRFTokenVerificationException;
import com.gdssecurity.anticsrf.protections.CSRFProtection;

public interface J2EECSRFProtection {

	public void setRequestObject(HttpServletRequest req);
	public boolean verifyCSRFToken() throws CSRFTokenVerificationException;
	public String generateCSRFToken() throws CSRFTokenGenerationException;
	public String getCSRFTokenParameterName();
	public String generateUrlSpecificCSRFToken(String url) throws CSRFTokenGenerationException;
	public String getCSRFToken() throws CSRFTokenGenerationException;
	public void setUserSeed(String userSeed);
}
