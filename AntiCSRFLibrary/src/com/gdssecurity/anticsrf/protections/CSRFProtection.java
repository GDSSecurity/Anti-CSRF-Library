package com.gdssecurity.anticsrf.protections;

import com.gdssecurity.anticsrf.exceptions.CSRFTokenGenerationException;
import com.gdssecurity.anticsrf.exceptions.CSRFTokenVerificationException;

public interface CSRFProtection 
{
	public boolean verifyCSRFToken(String url, String tokenFromUser) throws CSRFTokenVerificationException;
	public String generateCSRFToken() throws CSRFTokenGenerationException;
	public String getCSRFTokenParameterName();
	public String generateUrlSpecificCSRFToken(String url) throws CSRFTokenGenerationException;
}