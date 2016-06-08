package com.gdssecurity.anticsrf.utils;

public class StringUtil {
    public static String stripNewlines(String str)
    {
        if(str == null)
        {
            return "";
        }

        return str.replaceAll("(\\r|\\n)", "");
    }
}
