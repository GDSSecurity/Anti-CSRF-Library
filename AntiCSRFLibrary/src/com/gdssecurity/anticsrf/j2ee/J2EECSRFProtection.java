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
