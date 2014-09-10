/**
 * 
 */
package com.redhat.it.jboss.loginModules;

import net.sourceforge.jradiusclient.RadiusAttributeValues;
import net.sourceforge.jradiusclient.RadiusClient;
import net.sourceforge.jradiusclient.RadiusPacket;
import net.sourceforge.jradiusclient.exception.InvalidParameterException;
import net.sourceforge.jradiusclient.exception.RadiusException;
import net.sourceforge.jradiusclient.packets.PapAccessRequest;
import org.jboss.logging.Logger;
import org.jboss.security.SimpleGroup;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.CredentialExpiredException;
import javax.security.auth.login.LoginException;
import javax.security.jacc.PolicyContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Map;

/**
 * @author jdetiber
 * @author mcirioli
 *
 */
public class JbossRadiusLoginModule extends UsernamePasswordLoginModule {
	public static final String RADIUS_HOSTNAME = "hostName";
	public static final String RADIUS_SECONDARY_HOSTNAME = "secondaryHostName";
	public static final String RADIUS_SHARED_SECRET = "sharedSecret";
	public static final String RADIUS_AUTH_PORT = "authPort";
	public static final String RADIUS_ACCOUNTING_PORT = "acctPort";
	public static final String RADIUS_NUM_RETRIES = "numRetries";
	public static final String AUTH_ROLE_NAME = "authRoleName";
	public static final int MAX_CHALLENGE_ATTEMPTS = 3;
    private Logger logger = Logger.getLogger(JbossRadiusLoginModule.class);
    public static final String REPLICATED_SESSION_FLAG = "RedHatSAMLSession";

	private RadiusClient radiusClient;
	private int challengeAttempts = 0;

	private static final String[] ALL_VALID_OPTIONS = {
		RADIUS_HOSTNAME, RADIUS_SHARED_SECRET, RADIUS_AUTH_PORT,
		RADIUS_ACCOUNTING_PORT, RADIUS_NUM_RETRIES, AUTH_ROLE_NAME,
                RADIUS_SECONDARY_HOSTNAME
	};

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String,?> sharedState, Map<String,?> options) {
        logger.info("initiailize!");
		addValidOptions(ALL_VALID_OPTIONS);
		super.initialize(subject, callbackHandler, sharedState, options);
	}

	/* (non-Javadoc)
	 * @see org.jboss.security.auth.spi.AbstractServerLoginModule#getRoleSets()
	 */
	@Override
	protected Group[] getRoleSets() throws LoginException {
		SimpleGroup userRoles = new SimpleGroup("Roles");
		String roleName = (String)options.get(AUTH_ROLE_NAME);
		try {
			Principal p = super.createIdentity(roleName);
			logger.info("Assign user to role " + roleName);
			userRoles.addMember(p);
		} 
		catch (Exception e) {
			logger.info("Failed to create principal: " + roleName, e);
		}

		Group[] roleSets = {userRoles};
		return roleSets;
	}

	/** Overridden to return an empty password string as typically one cannot
     obtain a user's password. We also override the validatePassword so
     this is ok.
     
     ** changed by mike cirioli 9.12.2013
     ** to support password stacking all modules should return the same constant password
     
     @return an constant string, all login modules should use this same string
	 */
	@Override
	protected String getUsersPassword() throws LoginException {
        logger.info("getUsersPassword returning empty string always");
		return "";
	}

	@Override
	protected boolean validatePassword(String inputPassword, String expectedPassword){
		boolean isValid = true;
        Throwable validationError = null;
                
		logger.info("In validatePassword");
		logger.info("Username: "+getUsername());

        // does user have a valid replicated session?
        // added by mike cirioli
        // to work around session replication issue with radius auth we first check to see if a
        // special session attribute exists, if it does then it indicates this session exists
        // already and so we return TRUE straight away
        // if it does not, then we set it and proceed to properly authenticate the user

        HttpServletRequest request = null;
        HttpSession session = null;
        try {
            //request = (HttpServletRequest) PolicyContext.getContext(SecurityConstants.WEB_REQUEST_KEY);
            request = (HttpServletRequest) PolicyContext.getContext("javax.servlet.http.HttpServletRequest");
            Subject subject = (Subject) PolicyContext.getContext("javax.security.auth.Subject.container");
            logger.info("subject: " + subject);

            session = request.getSession(false);
            

            logger.info("Session ID == [" + session.getId() + "]");
//            logger.info("about to dump session....");
//            String session_info  = SessionDumper.dump(session);
//            logger.info("session info:" + session_info);

            logger.info("test for previous existing session");
            String sessionTest = (String) session.getAttribute(this.REPLICATED_SESSION_FLAG);

            if (sessionTest != null) {
                logger.info("Found replicated session flag in session, will not try to replay auth");
                return(true);
            }


//            if (sessionTest == null) {
//                logger.info("sessionTest was null, so this must be a new or non-replicant session");
//                logger.info("setting replicated session flag");
//                session.setAttribute(this.REPLICATED_SESSION_FLAG,this.REPLICATED_SESSION_FLAG);
//            }
//            else {
//                logger.info("Found replicated session flag in session, will not try to replay auth");
//                return(true);
//            }
        }
        catch (Exception ex) {
            logger.error("Problem trying to test for existing session: " + ex.getMessage());
        }

		if(inputPassword != null){
			String[] hostnames = new String[] { (String)options.get(RADIUS_HOSTNAME), (String)options.get(RADIUS_SECONDARY_HOSTNAME)};
            for ( String hostname: hostnames){
    			try {
					logger.info("getting RadiusClient for "+hostname);
					radiusClient = new RadiusClient(
							hostname,
							Integer.parseInt((String)options.get(RADIUS_AUTH_PORT)),
							Integer.parseInt((String)options.get(RADIUS_ACCOUNTING_PORT)),
							(String)options.get(RADIUS_SHARED_SECRET));

					logger.info("getting AccessRequest");
					RadiusPacket accessRequest = new PapAccessRequest(getUsername(), inputPassword);
				
					logger.info("attempting radiusAuth");
					radiusAuth(accessRequest, Integer.parseInt((String)options.get(RADIUS_NUM_RETRIES)));

					isValid = true;
                    logger.info("setting replicated session flag");
                    session.setAttribute(this.REPLICATED_SESSION_FLAG,this.REPLICATED_SESSION_FLAG);
					break;
				}
				catch (Throwable e) {
					logger.info("caught exception: "+e.toString());
					isValid = false;
					validationError = e;
				}
			}
		}
		if (!isValid){
			super.setValidateError(validationError);
		}
		return isValid;
	}

	private void radiusAuth(RadiusPacket accessRequest, int numRetries) throws LoginException {
		logger.info("radiusAuth");
		try {
			RadiusPacket accessResponse = this.radiusClient.authenticate(accessRequest, numRetries);
			switch (accessResponse.getPacketType()) {
			case RadiusPacket.ACCESS_ACCEPT:
				logger.info("Auth successful");
				break;
			case RadiusPacket.ACCESS_REJECT:
				logger.info("Auth rejected");
				throw new CredentialExpiredException("Incorrect User Name or Password.");
			case RadiusPacket.ACCESS_CHALLENGE:
				logger.info("Auth challenged");
				if (this.challengeAttempts > MAX_CHALLENGE_ATTEMPTS) {
					this.challengeAttempts = 0;
					throw new LoginException("Maximum number of challenge retries exceeded.");
				}
				Callback[] callbacks = new Callback[1];
				String password = null;
				callbacks[0] = new PasswordCallback(String.valueOf(accessResponse.getAttribute(RadiusAttributeValues.REPLY_MESSAGE).getValue()),true);
				try {
					callbackHandler.handle(callbacks);
					password = String.valueOf(((PasswordCallback)callbacks[0]).getPassword());
					if (password == null) {
						//treat a null password as a zero length password
						password = new String("");
					}
					//finally clear the password
					((PasswordCallback)callbacks[0]).clearPassword();
				} catch(IOException ioex) {
					logger.info("IOException Caught");
					throw new LoginException(ioex.getMessage());
				} catch(UnsupportedCallbackException uscbex) {
					logger.info("UnsupportedCallbackException Caught");
					StringBuffer sb = new StringBuffer("Error: callback ");
					sb.append(uscbex.getCallback().toString());
					sb.append(" not supported.");
					throw new LoginException(sb.toString());
				} catch(Exception e) {
					logger.info("caught Exception: " + e.toString());
					throw new LoginException(e.toString());
				}

				this.challengeAttempts++;
				RadiusPacket challengeResponse = new PapAccessRequest(getUsername(),String.valueOf(password));
				this.radiusAuth(challengeResponse, 1);
				break;
			default:
				logger.info("Invalid response from RADIUS server");
				throw new LoginException("Received an Invalid response from the RADIUS Server.");
			}
		} catch(InvalidParameterException ivpex) {
			logger.info("InvalidParameterException caught");
			throw new LoginException(ivpex.getMessage());
		} catch(RadiusException rex) {
			logger.info("RadiusException caught");
			throw new LoginException(rex.getMessage());
		} catch(Exception e) {
			logger.info("caught Exception: "+ e.toString());
			throw new LoginException(e.getMessage());
		}
	}
}
