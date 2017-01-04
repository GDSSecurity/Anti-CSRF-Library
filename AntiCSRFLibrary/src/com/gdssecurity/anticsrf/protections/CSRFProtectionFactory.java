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


package com.gdssecurity.anticsrf.protections;

import com.gdssecurity.anticsrf.j2ee.J2EECSRFProtection;
import com.gdssecurity.anticsrf.j2ee.J2EEHmacCSRFProtection;
import com.gdssecurity.anticsrf.j2ee.J2EESessionCSRFProtection;
import com.gdssecurity.anticsrf.utils.ConfigUtil;

public class CSRFProtectionFactory 
{
	public static J2EECSRFProtection getCSRFProtection()
	{
		if(ConfigUtil.isHmacMode())
		{
			return new J2EEHmacCSRFProtection();
		}
		
		// Session based Protection mode is the default
		return new J2EESessionCSRFProtection();
	}
}
