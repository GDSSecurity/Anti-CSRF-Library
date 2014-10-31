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
