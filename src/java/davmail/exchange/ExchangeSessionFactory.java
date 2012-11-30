/*
 * DavMail POP/IMAP/SMTP/CalDav/LDAP Exchange Gateway
 * Copyright (C) 2009  Mickael Guessant
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package davmail.exchange;

import davmail.BundleMessage;
import davmail.Settings;
import davmail.exception.DavMailAuthenticationException;
import davmail.exception.DavMailException;
import davmail.exception.WebdavNotAvailableException;
import davmail.exchange.dav.DavExchangeSession;
import davmail.exchange.ews.EwsExchangeSession;
import davmail.http.DavGatewayHttpClientFacade;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * Create ExchangeSession instances.
 */
public final class ExchangeSessionFactory {
	
    private static final Object LOCK = new Object();
    private static final Map<PoolKey, ExchangeSession> POOL_MAP = new HashMap<PoolKey, ExchangeSession>();
    
    private static Map<String, Boolean> configChecked = new HashMap<String, Boolean>();
    private static Map<String, Boolean> errorSent = new HashMap<String, Boolean>();

    static class PoolKey {
        final String url;
        final String userName;
        final String password;

        PoolKey(String url, String userName, String password) {
            this.url = url;
            this.userName = userName;
            this.password = password;
        }

        @Override
        public boolean equals(Object object) {
            return object == this ||
                    object instanceof PoolKey &&
                            ((PoolKey) object).url.equals(this.url) &&
                            ((PoolKey) object).userName.equals(this.userName) &&
                            ((PoolKey) object).password.equals(this.password);
        }

        @Override
        public int hashCode() {
            return url.hashCode() + userName.hashCode() + password.hashCode();
        }
    }

    private ExchangeSessionFactory() {
    }

    /**
     * Create authenticated Exchange session
     *
     * @param userName user login
     * @param password user password
     * @return authenticated session
     * @throws IOException on error
     */
    public static ExchangeSession getInstance(String userName, String password) throws IOException {
        String baseUrl = getUrl(userName);
        if (Settings.getBooleanProperty("davmail.server")) {
            return getInstance(baseUrl, userName, password);
        } else {
            // serialize session creation in workstation mode to avoid multiple OTP requests
            synchronized (LOCK) {
                return getInstance(baseUrl, userName, password);
            }
        }
    }

//    private static Connection getNewConnection() throws SQLException, ClassNotFoundException {
//    	String url = Settings.getProperty("davmail.database.url");
//    	String username = Settings.getProperty("davmail.database.username");
//    	String password = Settings.getProperty("davmail.database.password");
//    	
//        Class.forName("com.mysql.jdbc.Driver");
//        return DriverManager.getConnection(url, username, password);
//    }
    
//    private static String QUERY = " SELECT server_address from users WHERE username = ? "; 
    
    private static String getUrl(String userName) throws DavMailException {
    	ExchangeSession.LOGGER.debug("Getting URL for userName: " + userName);
    	
    	String result = null;
    	try {
	    	HttpClient client = new DefaultHttpClient();
	    	HttpGet get = new HttpGet(Settings.getProperty("davmail.rest.url")+'/'+URLEncoder.encode(userName)+".json");
	    	HttpResponse response = client.execute(get);
	    	
	    	BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
	    	
	    	JSONObject jsonValue = null;
	    	try {
	    		JSONParser parser = new JSONParser();
	    		jsonValue = (JSONObject)parser.parse(reader);
	    		
	    		// TODO if user not found jsonValue is null, check and answer appropriately 
	    		ExchangeSession.LOGGER.debug("Received JSON answer: " + jsonValue.toString());
				
	    		boolean confirmed = (Boolean)jsonValue.get("confirmed");
	    		if (!confirmed) {
	    			ExchangeSession.LOGGER.debug("Account not yet confirmed");
	            	throw new DavMailException("EXCEPTION_CONFIRMATION_EXCEPTION");
	    		}
				result = (String)jsonValue.get("server_address");
	    	} catch (ParseException pe){
	    		ExchangeSession.LOGGER.debug("Exception while parsing username", pe);
	    	}
			
    	} catch (ClientProtocolException exc) {
    		ExchangeSession.LOGGER.error(exc);
    	} catch (IOException exc) {
    		ExchangeSession.LOGGER.warn("Exception while trying to get URL", exc);
        	BundleMessage message = new BundleMessage("EXCEPTION_REST_EXCEPTION", exc.getClass().getName(), exc.getMessage());
        	throw new DavMailException("EXCEPTION_DAVMAIL_CONFIGURATION", message);
		}
    	
    	if (result == null) {
    		throw new DavMailException("EXCEPTION_USERNAME_NOT_FOUND", userName);
    	}

    	ExchangeSession.LOGGER.debug("Got URL for userName: " + userName + ", it is: " + result);
    	return result;
    }
    
//    private static String getUrl(String userName) throws DavMailException {
//    	String result = null;
//    	try {
//    		Connection c = getNewConnection();
//    		
//    		c.setAutoCommit(false);
//            PreparedStatement s = c.prepareStatement(QUERY);
//            s.setString(1, userName);
//            
//            ResultSet r = s.executeQuery();
//            
//            if (r.first()) { 
//            	result = r.getString("server_address");
//            }
//            c.commit();
//        } catch (SQLException exc) {
//        	ExchangeSession.LOGGER.warn("Exception while trying to get URL", exc);
//        	BundleMessage message = new BundleMessage("EXCEPTION_DATABASE_SQL_EXCEPTION", exc.getClass().getName(), exc.getMessage());
//        	throw new DavMailException("EXCEPTION_DAVMAIL_CONFIGURATION", message);
//        } catch (ClassNotFoundException exc) {
//        	ExchangeSession.LOGGER.error(exc);
//        }
//    	
//    	if (result == null) {
//    		throw new DavMailException("EXCEPTION_USERNAME_NOT_FOUND", userName);
//    	}
//    	
//    	ExchangeSession.LOGGER.debug("Got URL for userName: " + userName + ", it is: " + result);
//    	return result; 
//    }
    
    private static String convertUserName(String userName) {
        String result = userName;
        // prepend default windows domain prefix
        String defaultDomain = Settings.getProperty("davmail.defaultDomain");
        if (userName.indexOf('\\') < 0 && defaultDomain != null) {
            result = defaultDomain + '\\' + userName;
        }
        return result;
    }

    /**
     * Create authenticated Exchange session
     *
     * @param baseUrl  OWA base URL
     * @param userName user login
     * @param password user password
     * @return authenticated session
     * @throws IOException on error
     */
    public static ExchangeSession getInstance(String baseUrl, String userName, String password) throws IOException {
        ExchangeSession session = null;
        try {

            PoolKey poolKey = new PoolKey(baseUrl, convertUserName(userName), password);

            synchronized (LOCK) {
                session = POOL_MAP.get(poolKey);
            }
            if (session != null) {
                ExchangeSession.LOGGER.debug("Got session " + session + " from cache");
            }

            if (session != null && session.isExpired()) {
                ExchangeSession.LOGGER.debug("Session " + session + " expired");
                session = null;
                // expired session, remove from cache
                synchronized (LOCK) {
                    POOL_MAP.remove(poolKey);
                }
            }

            if (session == null) {
                String enableEws = Settings.getProperty("davmail.enableEws", "auto");
                if ("true".equals(enableEws)) {
                    session = new EwsExchangeSession(poolKey.url, poolKey.userName, poolKey.password);
                } else {
                    try {
                        session = new DavExchangeSession(poolKey.url, poolKey.userName, poolKey.password);
                    } catch (WebdavNotAvailableException e) {
                        if ("auto".equals(enableEws)) {
                            ExchangeSession.LOGGER.debug(e.getMessage() + ", retry with EWS");
                            session = new EwsExchangeSession(poolKey.url, poolKey.userName, poolKey.password);
                        } else {
                            throw e;
                        }
                    }
                }
                ExchangeSession.LOGGER.debug("Created new session: " + session);
            }
            // successful login, put session in cache
            synchronized (LOCK) {
                POOL_MAP.put(poolKey, session);
            }
            // session opened, future failure will mean network down
            configChecked.put(baseUrl, true);
            // Reset so next time an problem occurs message will be sent once
            errorSent.put(baseUrl, false);
        } catch (DavMailAuthenticationException exc) {
            throw exc;
        } catch (DavMailException exc) {
            throw exc;
        } catch (IllegalStateException exc) {
            throw exc;
        } catch (NullPointerException exc) {
            throw exc;
        } catch (Exception exc) {
        	ExchangeSession.LOGGER.debug("Exception occurred trying to open Exchange session ", exc);
            handleNetworkDown(baseUrl, exc);
        }
        return session;
    }

    /**
     * Get a non expired session.
     * If the current session is not expired, return current session, else try to create a new session
     *
     * @param currentSession current session
     * @param userName       user login
     * @param password       user password
     * @return authenticated session
     * @throws IOException on error
     */
    public static ExchangeSession getInstance(ExchangeSession currentSession, String userName, String password)
            throws IOException {
        ExchangeSession session = currentSession;
        
        String baseUrl = getUrl(userName);
        try {
            if (session.isExpired()) {
                ExchangeSession.LOGGER.debug("Session " + session + " expired, trying to open a new one");
                session = null;
                PoolKey poolKey = new PoolKey(baseUrl, userName, password);
                // expired session, remove from cache
                synchronized (LOCK) {
                    POOL_MAP.remove(poolKey);
                }
                session = getInstance(userName, password);
            }
        } catch (DavMailAuthenticationException exc) {
            ExchangeSession.LOGGER.debug("Unable to reopen session", exc);
            throw exc;
        } catch (Exception exc) {
            ExchangeSession.LOGGER.debug("Unable to reopen session", exc);
            handleNetworkDown(baseUrl, exc);
        }
        return session;
    }

//    /**
//     * Send a request to Exchange server to check current settings.
//     *
//     * @throws IOException if unable to access Exchange server
//     */
//    public static void checkConfig() throws IOException {
//        String url = Settings.getProperty("davmail.url");
//        if (url == null || (!url.startsWith("http://") && !url.startsWith("https://"))) {
//             throw new DavMailException("LOG_INVALID_URL", url);
//        }
//        HttpClient httpClient = DavGatewayHttpClientFacade.getInstance(url);
//        GetMethod testMethod = new GetMethod(url);
//        try {
//            // get webMail root url (will not follow redirects)
//            int status = DavGatewayHttpClientFacade.executeTestMethod(httpClient, testMethod);
//            ExchangeSession.LOGGER.debug("Test configuration status: " + status);
//            if (status != HttpStatus.SC_OK && status != HttpStatus.SC_UNAUTHORIZED
//                    && !DavGatewayHttpClientFacade.isRedirect(status)) {
//                throw new DavMailException("EXCEPTION_CONNECTION_FAILED", url, status);
//            }
//            // session opened, future failure will mean network down
//            configChecked = true;
//            // Reset so next time an problem occurs message will be sent once
//            errorSent = false;
//        } catch (Exception exc) {
//            handleNetworkDown(exc);
//        } finally {
//            testMethod.releaseConnection();
//        }
//    }

    private static void handleNetworkDown(String baseUrl, Exception exc) throws DavMailException {
        if (!checkNetwork() || (configChecked.get(baseUrl) != null && configChecked.get(baseUrl))) {
            ExchangeSession.LOGGER.warn(BundleMessage.formatLog("EXCEPTION_NETWORK_DOWN"));
            // log full stack trace for unknown errors
            if (!((exc instanceof UnknownHostException)||(exc instanceof NetworkDownException))) {
                ExchangeSession.LOGGER.debug(exc, exc);
            }
            throw new NetworkDownException("EXCEPTION_NETWORK_DOWN");
        } else {
            BundleMessage message = new BundleMessage("EXCEPTION_CONNECT", exc.getClass().getName(), exc.getMessage());
            if (errorSent.get(baseUrl) != null && errorSent.get(baseUrl)) {
                ExchangeSession.LOGGER.warn(message);
                throw new NetworkDownException("EXCEPTION_DAVMAIL_CONFIGURATION", message);
            } else {
                // Mark that an error has been sent so you only get one
                // error in a row (not a repeating string of errors).
                errorSent.put(baseUrl, true);
                ExchangeSession.LOGGER.error(message);
                throw new DavMailException("EXCEPTION_DAVMAIL_CONFIGURATION", message);
            }
        }
    }

    /**
     * Get user password from session pool for SASL authentication
     *
     * @param userName Exchange user name
     * @return user password
     */
    public static String getUserPassword(String userName) {
        String fullUserName = convertUserName(userName);
        for (PoolKey poolKey : POOL_MAP.keySet()) {
            if (poolKey.userName.equals(fullUserName)) {
                return poolKey.password;
            }
        }
        return null;
    }

    /**
     * Check if at least one network interface is up and active (i.e. has an address)
     *
     * @return true if network available
     */
    static boolean checkNetwork() {
        boolean up = false;
        Enumeration<NetworkInterface> enumeration;
        try {
            enumeration = NetworkInterface.getNetworkInterfaces();
            while (!up && enumeration.hasMoreElements()) {
                NetworkInterface networkInterface = enumeration.nextElement();
                //noinspection Since15
                up = networkInterface.isUp() && !networkInterface.isLoopback()
                        && networkInterface.getInetAddresses().hasMoreElements();
            }
        } catch (NoSuchMethodError error) {
            ExchangeSession.LOGGER.debug("Unable to test network interfaces (not available under Java 1.5)");
            up = true;
        } catch (SocketException exc) {
            ExchangeSession.LOGGER.error("DavMail configuration exception: \n Error listing network interfaces " + exc.getMessage(), exc);
        }
        return up;
    }

    /**
     * Reset config check status and clear session pool.
     */
    public static void reset() {
    	// TODO reset all
    	
        configChecked = new HashMap<String, Boolean>();
        errorSent = new HashMap<String, Boolean>();
        POOL_MAP.clear();
    }
    
}
