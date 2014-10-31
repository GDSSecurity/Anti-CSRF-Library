package com.gdssecurity.anticsrf.utils;

import java.lang.String;
import java.text.StringCharacterIterator;
import java.text.CharacterIterator;
import java.lang.StringBuffer;

//
//AntiXSS for Java Version 2
//
//This is a port of the Microsoft AntiXSS library v1.5 for Java. 
//
//This should be compatible with JVMs implementing the Java 1.4 or greater
//
//Created by Justin Clarke on 18/11/2007. Last updated 19 April 2008
//Copyright (c) 2007,2008 Gotham Digital Science. All rights reserved.
//

public class Encoder 
{
	// Private variables
	private static String EmptyString_JavaScript = "";
	private static String EmptyString = "";
	private static StringBuffer strb;
	private static StringCharacterIterator sci;

	private static String EncodeHtml(String strInput) {
		if (strInput.length() == 0) {
			return EmptyString;
		}
		StringBuffer builder = new StringBuffer(strInput.length() * 2);
		CharacterIterator it = new StringCharacterIterator(strInput);
		for (char ch = it.first(); ch != CharacterIterator.DONE; ch = it.next()) {
			if ((((ch > '`') && (ch < '{')) || ((ch > '@') && (ch < '[')))
					|| (((ch == ' ') || ((ch > '/') && (ch < ':'))) || (((ch == '.') || (ch == ',')) || ((ch == '-') || (ch == '_'))))) {
				builder.append(ch);
			} else {
				builder.append("&#" + (int) ch + ";");
			}
		}
		return builder.toString();
	}
	
	private static String EncodeHtmlWithNL(String strInput) {
		if (strInput.length() == 0) {
			return EmptyString;
		}
		StringBuffer builder = new StringBuffer(strInput.length() * 2);
		CharacterIterator it = new StringCharacterIterator(strInput);
		for (char ch = it.first(); ch != CharacterIterator.DONE; ch = it.next()) {
			if ((((ch > '`') && (ch < '{')) || ((ch > '@') && (ch < '[')))
					|| (((ch == ' ') || ((ch > '/') && (ch < ':'))) || (((ch == '.') || (ch == ',')) || ((ch == '-') || (ch == '_')))) || (ch == '\n')) {
				builder.append(ch);
			} else {
				builder.append("&#" + (int) ch + ";");
			}
		}
		return builder.toString();
	}

	private static String EncodeHtmlAttribute(String strInput) {
		if (strInput.length() == 0) {
			return EmptyString;
		}
		StringBuffer builder = new StringBuffer(strInput.length() * 2);
		CharacterIterator it = new StringCharacterIterator(strInput);
		for (char ch = it.first(); ch != CharacterIterator.DONE; ch = it.next()) {
			if ((((ch > '`') && (ch < '{')) || ((ch > '@') && (ch < '[')))
					|| (((ch > '/') && (ch < ':')) || (((ch == '.') || (ch == ',')) || ((ch == '-') || (ch == '_'))))) {
				builder.append(ch);
			} else {
				builder.append("&#" + (int) ch + ";");
			}
		}
		return builder.toString();
	}

	private static String EncodeJs(String strInput) {
		if (strInput.length() == 0) {
			return EmptyString_JavaScript;
		}
		
		// RON CHANGE: I'm not sure why the encode surrounds the data with single quotes..
		//StringBuffer builder = new StringBuffer("'");
		
		StringBuffer builder = new StringBuffer("");
		CharacterIterator it = new StringCharacterIterator(strInput);
		for (char ch = it.first(); ch != CharacterIterator.DONE; ch = it.next()) {
			if ((((ch > '`') && (ch < '{')) || ((ch > '@') && (ch < '[')))
					|| (((ch == ' ') || ((ch > '/') && (ch < ':'))) || (((ch == '.') || (ch == ',')) || ((ch == '-') || (ch == '_'))))) {
				builder.append(ch);
			} else if (ch > '\u007f') {
				builder.append("\\u" + TwoByteHex(ch));
			} else {
				builder.append("\\x" + SingleByteHex(ch));
			}
		}
		//builder.append("'");
		return builder.toString();
	}

	private static String EncodeUrl(String strInput) {
		if (strInput.length() == 0) {
			return EmptyString;
		}
		StringBuffer builder = new StringBuffer(strInput.length() * 2);
		CharacterIterator it = new StringCharacterIterator(strInput);
		for (char ch = it.first(); ch != CharacterIterator.DONE; ch = it.next()) {
			if ((((ch > '`') && (ch < '{')) || ((ch > '@') && (ch < '[')))
					|| (((ch > '/') && (ch < ':')) || (((ch == '.') || (ch == '-')) || (ch == '_')))) {
				builder.append(ch);
			} else if (ch > '\u007f') {
				builder.append("%u" + TwoByteHex(ch));
			} else {
				builder.append("%" + SingleByteHex(ch));
			}
		}
		return builder.toString();
	}

	/**
	 * Returns a string object encoded to be used in an HTML attribute.
	 * <p>
	 * This method will return characters a-z, A-Z, 0-9, full stop, comma, dash,
	 * and underscore unencoded, and encode all other character in decimal HTML
	 * entity format (i.e. < is encoded as &#60;).
	 * 
	 * @param s
	 *            a string to be encoded for use in an HTML attribute context
	 * @return the encoded string
	 */
	public static String HtmlAttributeEncode(String s) {
		return EncodeHtmlAttribute(s);
	}

	/**
	 * Returns a string object encoded to use in HTML.
	 * <p>
	 * This method will return characters a-z, A-Z, space, 0-9, full stop,
	 * comma, dash, and underscore unencoded, and encode all other character in
	 * decimal HTML entity format (i.e. < is encoded as &#60;).
	 * 
	 * @param s
	 *            a string to be encoded for use in an HTML context
	 * @return the encoded string
	 */
	public static String HtmlEncode(String s) {
		return EncodeHtml(s);
	}
	
	public static String HtmlEncodeWithNL(String s) {
		return EncodeHtmlWithNL(s);
	}

	/**
	 * Returns a string object encoded to use in JavaScript as a string.
	 * <p>
	 * This method will return characters a-z, A-Z, space, 0-9, full stop,
	 * comma, dash, and underscore unencoded, and encode all other character in
	 * a 2 digit hexadecimal escaped format for non-unicode characters (e.g.
	 * \x17), and in a 4 digit unicode format for unicode character (e.g.
	 * \u0177).
	 * <p>
	 * The encoded string will be returned enclosed in single quote characters
	 * (i.e. ').
	 * 
	 * @param s
	 *            a string to be encoded for use in a JavaScript context
	 * @return the encoded string
	 */
	public static String JavaScriptEncode(String s) {
		return EncodeJs(s);
	}

	private static String SingleByteHex(char c) {
		long num = c;
		return leftPad(Long.toString(num, 16), "0", 2);
	}

	private static String TwoByteHex(char c) {
		long num = c;
		return leftPad(Long.toString(num, 16), "0", 4);
	}

	/**
	 * Returns a string object encoded to use in a URL context.
	 * <p>
	 * This method will return characters a-z, A-Z, 0-9, full stop, dash, and
	 * underscore unencoded, and encode all other characters in short
	 * hexadecimal URL notation. for non-unicode character (i.e. < is encoded as
	 * %3c), and as unicode hexadecimal notation for unicode characters (i.e.
	 * %u0177).
	 * 
	 * @param s
	 *            a string to be encoded for use in a URL context
	 * @return the encoded string
	 */
	public static String UrlEncode(String s) {
		return EncodeUrl(s);
	}


	private static String leftPad(String stringToPad, String padder, int size) {
		if (padder.length() == 0) {
			return stringToPad;
		}
		strb = new StringBuffer(size);
		sci = new StringCharacterIterator(padder);

		while (strb.length() < (size - stringToPad.length())) {
			for (char ch = sci.first(); ch != CharacterIterator.DONE; ch = sci
					.next()) {
				if (strb.length() < size - stringToPad.length()) {
					strb.insert(strb.length(), String.valueOf(ch));
				}
			}
		}
		return strb.append(stringToPad).toString();
	}
	
	public static String stripNewlines(String str)
	{
		if(str == null)
		{
			return "";
		}
	    
		return str.replaceAll("(\\r|\\n)", "");
	}
}

