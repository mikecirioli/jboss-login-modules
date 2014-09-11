/**
 * 
 */
package org.picketlink.contrib.loginModules;

import org.jboss.logging.Logger;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;


/**
 * @author jdetiber
 * @author vkumar
 * @author mcirioli
 *
 * Jboss loginModules authenticator that validates username/password against redhat User Service via REST
 * 4.22.2013
 * 
 */

public class DebugLoginModule extends UsernamePasswordLoginModule {
	public static final String AUTH_ROLE_NAME = "authRoleName";
    private Logger logger = Logger.getLogger(DebugLoginModule.class);
	private static final String[] ALL_VALID_OPTIONS = {};

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String,?> sharedState, Map<String,?> options) {
    	logger.info("DebugLoginModule initialize!");
		addValidOptions(ALL_VALID_OPTIONS);

        logger.info("dumping shareState");
        Set keys = sharedState.keySet();
        for (Iterator i = keys.iterator();i.hasNext();) {
            String key = (String) i.next();
            Object value = (Object) sharedState.get(key);
            logger.info("key: [" + key + "]   value: [" + value.toString() + "]");
        }
        logger.info("done dumping sharedState");

        logger.info("getting subject prinicpals");
        Set principals = subject.getPrincipals();
        for (Iterator i = principals.iterator();i.hasNext();) {
            Principal p = (Principal) i.next();
            logger.info("principal.getName(): [" + p.getName()+ "]");
        }
        logger.info("done dumping subject prinicpals");

        super.initialize(subject, callbackHandler, sharedState, options);


	}

	/* (non-Javadoc)
	 * @see org.jboss.security.auth.spi.AbstractServerLoginModule#getRoleSets()
	 */
	@Override
	protected Group[] getRoleSets() throws LoginException {
        logger.debug("debugLoginModule.getRoleSets()");
//		String roleName = (String)options.get(AUTH_ROLE_NAME);
//
//		SimpleGroup userRoles = new SimpleGroup("Roles");
//        Principal p = null;
//		try {
//            p = super.createIdentity(roleName);
//			logger.debug("Assign principal [" + p.getName() + "] to role [" + roleName + "]");
//			userRoles.addMember(p);
//		} catch (Exception e) {
//			logger.info("Failed to assign principal [" + p.getName() + "] to role [" + roleName + "]", e);
//		}

		Group[] roleSets = {};
		return roleSets;
	}

	/** Overridden to return an empty password string as typically one cannot
     obtain a user's password. We also override the validatePassword so
     this is ok.
     @return an empty password String
	 */
	@Override
	protected String getUsersPassword() throws LoginException {
	    logger.info("getUsersPassword() [returning empty string always]");
		return "";
	}

	/*
	 * (non-Javadoc)
	 * @see org.jboss.security.auth.spi.UsernamePasswordLoginModule#validatePassword(java.lang.String, java.lang.String)
	 * 
	 * Takes users password and validates it using the redhat REST user service
	 * this method should not typically be called, it is used to stuff a fake role into the users 
	 */
	 
	@Override
	protected boolean validatePassword(String inputPassword, String expectedPassword){
        logger.info("validatePassword() [returning false always]");
        return false;
    }
}
