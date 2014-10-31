package com.gdssecurity.anticsrf.utils;

public class SecureCompare 
{
	public static boolean isEqual(byte[] a, byte[] b) 
	{
	    if (a.length != b.length) 
	    {
	        return false;
	    }

	    int result = 0;
	    
	    for (int i = 0; i < a.length; i++) 
	    {
	      result |= a[i] ^ b[i];
	    }
	    
	    return result == 0;
	}
}
