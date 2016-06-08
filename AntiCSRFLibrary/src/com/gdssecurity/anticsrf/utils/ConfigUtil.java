package com.gdssecurity.anticsrf.utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Properties;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.gdssecurity.anticsrf.exceptions.CSRFConfigException;
import com.gdssecurity.anticsrf.exceptions.CSRFSignerException;
import com.gdssecurity.anticsrf.utils.StringUtil;

public class ConfigUtil 
{
	private static final Logger LOG = Logger.getLogger(ConfigUtil.class.getName());
	private static Properties csrfConfig = new Properties();
	private static HashMap<String,Integer> exemptUrls = new HashMap<String,Integer>();
	private static HashMap<String,Long> urlSpecificConfig = new HashMap<String,Long>();
	private static HashMap<String,Integer> oneTimeUseConfig = new HashMap<String,Integer>();
	private static KeyczarWrapper keyczarWrapper;

	
	public static Properties getConfig()
	{
		return csrfConfig;
	}
	
	public static void loadConfig(String configFilename) throws CSRFConfigException
	{
		try
		{
			FileInputStream fis = new FileInputStream(configFilename);
			loadConfig(fis);
			fis.close();
		}
		catch (FileNotFoundException ex)
		{
			String err = "CSRF Configuration file is not found, exception="+ex.getMessage();
			LOG.severe(err);
			throw new CSRFConfigException(err);
		}
		catch (IOException ex)
		{
			String err = "Failed to properly read CSRF Configuration file"+
					", exception="+ex.getMessage();
			LOG.severe(err);
			throw new CSRFConfigException(err);
		} 
	}
	
	/*
	 * New public loadConfig overload that accepts a configuration object to 
	 * allow programmatic configuration. Currently, only the protection mode 
	 * and the keyfile config values are overridden from the config object.
	 */
	public static void loadConfig(Config config) throws CSRFConfigException
	{
		try
		{
			String emptyConfigString = "<anticsrf></anticsrf>";
			loadConfig(new ByteArrayInputStream(emptyConfigString.getBytes("UTF-8")), config);
		}
		catch (Exception ex)
		{
			throw new CSRFConfigException(ex);
		}
	}
	
	public static void loadConfig(InputStream is) throws CSRFConfigException
	{
		loadConfig(is, null);
	}
	
	private static void loadConfig(InputStream is, Config overrides) throws CSRFConfigException
	{
		LOG.info("Loading XML Config File");
		try
		{
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
			dbFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.parse(is);
			doc.getDocumentElement().normalize();
			
			NodeList nl = doc.getElementsByTagName(Constants.CONF_MODE);
			Node node = nl.item(0);
					
			String mode = Constants.MODES.session.toString(); // session based protection is the default mode		
			String modeOverride = (overrides != null ? overrides.getProtectionMode() : null);
			
			if (modeOverride != null)
			{
				mode = modeOverride;
			}
			else if (node != null)
			{
				mode = node.getFirstChild().getNodeValue();
			}
			
			Constants.MODES.valueOf(mode); // Make sure it is an existent mode
			csrfConfig.setProperty(Constants.CONF_MODE, mode);
			
			Element docElement = (Element)doc.getDocumentElement();
			
			loadLoggingConfiguration(docElement);
			
			if(isHmacMode())
			{
				handleHMACConfigLoading(doc, overrides);
			}
			else if(isSessionMode())
			{
				handleSessionConfigLoading(doc);
			}
			
			readXmlUrlListing(docElement, Constants.CONF_EXEMPTURLS);

			String tokenRequestAttribute = readElementTextValue(docElement, Constants.CONF_TOKEN_REQATTR);
			if(tokenRequestAttribute.equals("")) 
			{
				tokenRequestAttribute = Constants.CONF_DEFAULT_TOKEN_REQATTR;
			}
			
			String tokenRequestParameter = readElementTextValue(docElement, Constants.CONF_TOKEN_PARAM);
			if(tokenRequestParameter.equals(""))
			{
				tokenRequestParameter = Constants.CONF_DEFAULT_TOKEN_PARAM;
			}
			
			String monitorMode = readElementAttributeTextValue(docElement, Constants.CONF_MONITORMODE, "enabled");
			
			if(monitorMode.equals(""))
			{
				monitorMode = "no"; // Disabled by default
			}
			
			if(!monitorMode.equals("yes") && !monitorMode.equals("no"))
			{
				throw new CSRFConfigException("Invalid monitormode attribute entered. " +
						"We are expecting either 'yes' or 'no'. EnteredValue="+monitorMode);
			}
					
			String errorValue = "";
			String errorMode = readElementAttributeTextValue(docElement, Constants.CONF_ERROR, "mode");
			if(errorMode == null)
			{
				errorMode = "";
			}
			
			if(errorMode.equals("redirect") || errorMode.equals("forward"))
			{
				errorValue = getValidatedUrl(readElementTextValue(docElement, Constants.CONF_ERROR));
				
			}
			else if(errorMode.equals("status_code"))
			{
				errorValue = readElementTextValue(docElement, Constants.CONF_ERROR);
				if(!validateTimeout(errorValue))
				{
					throw new CSRFConfigException("Invalid StatusCode passed within configuration error attribute. Submitted StatusCode="+errorValue);
				}
			}
						
			csrfConfig.setProperty(Constants.CONF_ERROR, errorMode);
			csrfConfig.setProperty(Constants.CONF_ERRORVAL, errorValue);
			csrfConfig.setProperty(Constants.CONF_TOKEN_PARAM, tokenRequestParameter );
			csrfConfig.setProperty(Constants.CONF_TOKEN_REQATTR, tokenRequestAttribute);
			csrfConfig.setProperty(Constants.CONF_MONITORMODE, monitorMode);

			printConfiguration();
			
		}
		catch(CSRFSignerException ex)
		{
			String err = "Error loading Keyczar Keyfile: exception="+ex.getMessage();
			LOG.severe(err);
			throw new CSRFConfigException(err);
		}
		catch (ParserConfigurationException ex) 
		{
			String err = "Failed to parse CSRF Configuration file, exception="+ex.getMessage();
			LOG.severe(err);
			throw new CSRFConfigException(err);
		} 
		catch (IOException ex)
		{
			String err = "Failed to properly read CSRF Configuration file"+
					", exception="+ex.getMessage();
			LOG.severe(err);
			throw new CSRFConfigException(err);
		} 
		catch (SAXException ex) 
		{
			String err = "Failed to parse CSRF Configuration file, exception="+ex.getMessage();
			LOG.severe(err);
			throw new CSRFConfigException(err);
		}
	}
	
	private static void loadLoggingConfiguration(Element element) throws SecurityException, IOException
	{
		String loggingConfigPath = readElementTextValue(element, Constants.JAVA_LOGGING_CONF);

		if(!loggingConfigPath.equals(""))
		{
			LOG.info("Custom Java logging configuration file specified");
			File loggingConfigFile = new File(loggingConfigPath);
			if(loggingConfigFile.exists())
		    {
				FileInputStream loggingConfigFS = new FileInputStream(loggingConfigFile);                                
				LogManager.getLogManager().readConfiguration(loggingConfigFS);
		    }
			else
			{
				LOG.info("Error loading Java Logging Configuration file. " +
						"Could not find the following the specified filename: "+ loggingConfigFile);
			}
			
			csrfConfig.setProperty(Constants.JAVA_LOGGING_CONF, loggingConfigPath);
		}
	}
	
	public static void handleHMACConfigLoading(Document doc, Config overrides) throws CSRFConfigException, CSRFSignerException
	{
		NodeList nl = doc.getElementsByTagName(Constants.CONF_HMACSETTINGS);
		Node node = nl.item(0);
		
		// Set some default values
		csrfConfig.setProperty(Constants.CONF_HMAC_USERSEED_ATTR, Constants.CONF_DEFAULT_USERSEED_ATTR);
		csrfConfig.setProperty(Constants.CONF_HMAC_SITEWIDE_TIMEOUT, Constants.CONF_DEFAULT_TOKENTIMEOUT);
		
		if(node != null && node.getNodeType() == Node.ELEMENT_NODE)
		{
			String hmacKeyfile = readElementTextValue((Element)node, Constants.CONF_HMAC_KEYFILE);
			setHMACKeyFile(hmacKeyfile);
			
			String seedAttributeName = readElementTextValue((Element)node, Constants.CONF_HMAC_USERSEED_ATTR);
			if(!seedAttributeName.equals(""))
			{
				csrfConfig.setProperty(Constants.CONF_HMAC_USERSEED_ATTR, seedAttributeName);
			}
			
			String sitewideTimeout = readElementTextValue((Element)node, Constants.CONF_HMAC_SITEWIDE_TIMEOUT);
			if(!validateTimeout(sitewideTimeout))
			{
				throw new CSRFConfigException("Invalid Sitewide timeout value submitted. SubmittedTimeout="
						+sitewideTimeout);
			}
			
			if(!sitewideTimeout.equals(""))
			{
				csrfConfig.setProperty(Constants.CONF_HMAC_SITEWIDE_TIMEOUT, sitewideTimeout);
			}
			
			readXmlUrlListing((Element) node, Constants.CONF_URLSPECIFIC);
		}
		
		// Apply overrides		
		if (overrides != null)
		{
			String hmacKeyFile = overrides.getHMACKeyFile();
			
			if (hmacKeyFile != null && hmacKeyFile != "")
			{
				setHMACKeyFile(hmacKeyFile);
			}
		}
	}
	
	private static void setHMACKeyFile(String hmacKeyFile) throws CSRFConfigException, CSRFSignerException
	{
		if(hmacKeyFile == null || hmacKeyFile == "")
		{
			String err = "HMAC-mode CSRF Protection requires Keyczar HMAC File to " +
					"be define within the configuration file";
			LOG.severe(err);
			throw new CSRFConfigException(err);
		}
		
		csrfConfig.setProperty(Constants.CONF_HMAC_KEYFILE, hmacKeyFile);
		keyczarWrapper = new KeyczarWrapper(hmacKeyFile);
	}

	private static void handleSessionConfigLoading(Document doc) throws CSRFConfigException
	{
		NodeList nl = doc.getElementsByTagName(Constants.CONF_SESSIONSETTINGS);
		Node node = nl.item(0);
		
		if(node != null && node.getNodeType() == Node.ELEMENT_NODE)
		{
			readXmlUrlListing((Element) node, Constants.CONF_SESSION_ONETIMEUSE);
			readXmlUrlListing((Element) node, Constants.CONF_URLSPECIFIC);
		}
	}
	
	
	private static String readElementTextValue(Element element, String elementName)
	{
		try
		{
			if(element != null)
			{
				return (String)element.getElementsByTagName(elementName).item(0).getFirstChild().getNodeValue();
			}
		}
		catch(NullPointerException ex){};
		
		return "";
	}
	
	private static String readElementAttributeTextValue(Element element, String elementName, String attributeName)
	{
		try
		{
			if(element != null)
			{
				Node node = element.getElementsByTagName(elementName).item(0);
				return (String)node.getAttributes().getNamedItem(attributeName).getFirstChild().getNodeValue();
			}
		}
		catch(NullPointerException ex){} // Purposely left empty since we just want to return an empty string
		
		return "";
	}
	
	private static void readXmlUrlListing(Element element, String listName) 
	throws CSRFConfigException
	{
		NodeList nl = element.getElementsByTagName(listName);
		if(nl.getLength() > 0) {
			Element urlSpecificElement = (Element)nl.item(0);
			
			NodeList urlNodelist = urlSpecificElement.getElementsByTagName("url");
			
			for(int i = 0; i < urlNodelist.getLength(); i++)
			{
				Node urlNode = urlNodelist.item(i);
				String timeout = "0";
				String url = getValidatedUrl(urlNode.getFirstChild().getNodeValue());

				if(isHmacMode())
				{
					try
					{
						timeout = urlNode.getAttributes().getNamedItem("timeout").getFirstChild().getNodeValue();
						if(!validateTimeout(timeout))
						{
							throw new CSRFConfigException("Invalid URL Specific timeout value specified. URL="
									+ url + ", EnteredTimeout="+timeout);
						}
					}
					catch(NullPointerException ex)
					{
						// If no timeout was set, we use the sitewide value
						timeout = ConfigUtil.getProp(Constants.CONF_HMAC_SITEWIDE_TIMEOUT); 
					}		
				}
				
				if(listName.equals("urlspecific"))
				{
					if(isSessionMode() && oneTimeUseConfig.containsKey(url))
					{
						LOG.info("Not setting URL as URL Specific because has already been set as a OneTimeUse URL. url="+url);
						continue;
					}
					
					urlSpecificConfig.put(url, Long.parseLong(timeout));
				}
				else if(listName.equals("onetimeuse"))
				{
					oneTimeUseConfig.put(url, new Integer(0));
				}
				else if(listName.equals("exempt_urls"))
				{
					exemptUrls.put(url, new Integer(0));
				}
			}
		}
	}

	private static boolean validateTimeout(String timeout)
	{
		try
		{
			Long timeoutLong = Long.parseLong(timeout);
			if(timeoutLong > 0)
			{
				return true;
			}
		}
		catch(NumberFormatException ex)
		{
			LOG.severe("Invalid Timout value submitted. Value should be a positive numeric value. EnteredValue="+timeout.toString());
		}
		
		return false;
	}
	
	private static String getValidatedUrl(String url) throws CSRFConfigException
	{
		url.replaceAll("\\s", ""); // Strip out the whitespace
		
		if( !url.startsWith("/") )
		{
			throw new CSRFConfigException("Invalid URL is not in a valid format."
						+ "We are expecting a relative path and should therefore begin with a '/'. EnteredUrl="+url);
		}
		
		Pattern pattern = Pattern.compile("^[A-Za-z1-9_.~:/#@=;,'\\-\\?\\[\\]\\+\\*\\{\\}\\&\\$\\|]+$");
		Matcher matcher = pattern.matcher(url);
		
		if(!matcher.matches())
		{
			throw new CSRFConfigException("Invalid character passed in the URL. EnteredUrl="+url);
		}
		
		return url;
	}
	
	private static void printConfiguration()
	{
		StringBuffer str = new StringBuffer("\n============\nAntiCSRF Configuration\n============\n" );
		str.append( Constants.CONF_MODE + ": " + csrfConfig.getProperty(Constants.CONF_MODE) + "\n" );
		str.append( Constants.CONF_TOKEN_REQATTR + ": " + csrfConfig.getProperty(Constants.CONF_TOKEN_REQATTR) + "\n" );
		str.append( Constants.CONF_TOKEN_PARAM + ": " + csrfConfig.getProperty(Constants.CONF_TOKEN_PARAM) + "\n" );
		str.append( Constants.CONF_ERROR + ": " + csrfConfig.getProperty(Constants.CONF_ERROR) + "\n" );
		str.append( Constants.CONF_ERRORVAL + ": " + csrfConfig.getProperty(Constants.CONF_ERRORVAL) + "\n" );
		str.append( Constants.JAVA_LOGGING_CONF + ": " + csrfConfig.getProperty(Constants.JAVA_LOGGING_CONF) + "\n" );
		str.append( Constants.CONF_MONITORMODE + ": " + csrfConfig.getProperty(Constants.CONF_MONITORMODE) + "\n" );

		str.append( "\n-Exempt URLs-\n" );
		
		for(String url : exemptUrls.keySet())
		{
			str.append( "url: " + url + "\n" );
		}
				
		if(isHmacMode())
		{
			str.append( "\n++HMAC Protection Mode Settings++\n" );
			str.append( Constants.CONF_HMAC_KEYFILE + ": " + csrfConfig.getProperty(Constants.CONF_HMAC_KEYFILE) + "\n" );
			str.append( Constants.CONF_HMAC_SITEWIDE_TIMEOUT + ": " + csrfConfig.getProperty(Constants.CONF_HMAC_SITEWIDE_TIMEOUT) + "\n" );
			str.append( Constants.CONF_HMAC_USERSEED_ATTR + ": " + csrfConfig.getProperty(Constants.CONF_HMAC_USERSEED_ATTR) + "\n" );

			str.append( "\n--URL Specific Configuration--\n" );
			for(String url : urlSpecificConfig.keySet())
			{
				str.append( "url: " + url + "   timeout: "+ urlSpecificConfig.get(url) + "\n" );
			}
		}
		else if(isSessionMode())
		{
			str.append( "\n++Session Protection Mode Settings++\n" );
			
			str.append( "\n--URL Specific Configuration--\n" );
			for(String url : urlSpecificConfig.keySet())
			{
				str.append( "url: " + url + "\n" );
			}
			
			str.append( "\n--One Time Use Configuration--\n" );
			for(String url : oneTimeUseConfig.keySet())
			{
				str.append( "url: " + url + "\n" );
			}
		}
		LOG.info(str.toString());
		
	}
	
	public static String getProp(String configProperty)
	{
        try {
            return csrfConfig.getProperty(configProperty);
        } catch (Exception e) {
            LOG.warning("Failed to find property: " + configProperty + " exmsg= " + e.getMessage());
            return Constants.defaultConfigs.get(configProperty);
        }
	}
	
	public static KeyczarWrapper getKeyczarWrapper()
	{
		return keyczarWrapper;
	}
	
	public static boolean isURLExempt(String url)
	{		
		if( exemptUrls.containsKey(url) )
		{
			LOG.fine("Current url is configured to be exempt from CSRF Protection, url="+url);
			return true;
		}
		
		return false;
	}
	
	public static boolean hasOneTimeUseConfig(String url)
	{
		LOG.fine("About to check if token is configured for OneTimeUser: RequestURI="+StringUtil.stripNewlines(url));
		return oneTimeUseConfig.containsKey(url);
	}
	
	public static boolean hasUrlSpecificConfig(String url)
	{
		return urlSpecificConfig.containsKey(url);
	}
	
	public static Long getUrlSpecificConfig(String url)
	{
		return urlSpecificConfig.get(url);
	}
	
	public static boolean isHmacMode()
	{
		return csrfConfig.getProperty(Constants.CONF_MODE).equals(Constants.MODES.hmac.toString());
	}
	
	public static boolean isSessionMode()
	{
		return csrfConfig.getProperty(Constants.CONF_MODE).equals(Constants.MODES.session.toString());
	}
}
