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



package com.gdssecurity.anticsrf.utils;

import java.util.HashMap;
import java.util.Map;

public class Constants 
{
	public static enum MODES {
		session, hmac
	}
	
	public static final String CONF_INITPARAMNAME = "anticsrf_config";
	public static final String CONFIGNAME = "anticsrf.xml";
	public static final String JAVA_LOGGING_CONF = "logging_configfile";
	public static final String WEB_CONTAINER = "WEB-INF";
	public static final String FILE_SEPARATOR = System.getProperty("file.separator");
	
	public static final String CONF_HMACSETTINGS = "hmac_settings";
	public static final String CONF_HMAC_USERSEED_ATTR = "seed_attribute_name";
	public static final String CONF_HMAC_SITEWIDE_TIMEOUT = "sitewide_timeout";
	public static final String CONF_HMAC_KEYFILE = "keyfile";
	
	public static final String CONF_SESSIONSETTINGS = "session_settings";
	public static final String CONF_SESSION_ONETIMEUSE = "onetimeuse";
		
	public static final String CONF_MODE = "mode";
	public static final String CONF_MONITORMODE = "monitormode";
	public static final String CONF_ERROR = "error";
	public static final String CONF_ERRORVAL = "errorval";
	public static final String CONF_EXEMPTURLS= "exempt_urls";
	public static final String CONF_TOKEN_REQATTR = "token_attribute";
	public static final String CONF_TOKEN_PARAM = "token_parametername";
	public static final String CONF_URLSPECIFIC = "urlspecific";
	public static final String CONF_ERROR_AJAX = "ajax";

	public static final String CONF_DEFAULT_TOKEN_REQATTR = "anticsrftoken";
	public static final String CONF_DEFAULT_USERSEED_ATTR = "userseed";
	public static final String CONF_DEFAULT_TOKEN_PARAM = "tok";
	public static final String CONF_DEFAULT_TOKENTIMEOUT = "30";

    public static final Map<String, String> defaultConfigs;
    static
    {
    	defaultConfigs = new HashMap<String, String>();
    	defaultConfigs.put("token_attribute", "anticsrftoken");
    	defaultConfigs.put("userseed", "userseed");
    	defaultConfigs.put("token_parametername", "tok");
    	defaultConfigs.put("timeout", "30");
    	defaultConfigs.put("mode", "session");
    }

	
}
