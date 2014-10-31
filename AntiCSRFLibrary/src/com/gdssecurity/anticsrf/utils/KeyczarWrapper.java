package com.gdssecurity.anticsrf.utils;

import org.keyczar.Signer;
import org.keyczar.exceptions.KeyczarException;

import com.gdssecurity.anticsrf.exceptions.CSRFSignerException;

public class KeyczarWrapper {

	private Signer csrfSigner = null;
	
	public KeyczarWrapper(String hmacKeyfile) throws CSRFSignerException
	{
		try {
			csrfSigner = new Signer(hmacKeyfile);
		} catch (KeyczarException e) {
			throw new CSRFSignerException(e);
		}
	}
	
	public Signer getCSRFSigner()
	{
		return this.csrfSigner;
	}
	
}
