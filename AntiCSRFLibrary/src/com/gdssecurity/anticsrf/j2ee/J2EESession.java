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
