login-modules:  Additional login-modules of JBoss/PicketLink
===============================
Author: Michael Cirioli
Level: Beginner
Technologies:  JBoss EAP/WildFly, PicketLink
Summary: Additional JBoss login-modules providing Radius OTP authentication, static logins, static roles, debugging info
Source: <https://github.com/mikecirioli/jboss-login-modules>

What is it?
-----------
This project contains a number of JBoss EAP/WildFly login-modules that can be used to perform container level 
authentication and authorization.  

Included modules:

    JbossRadiusLoginModule - performs RADIUS OTP based authentication
    
    StaticLoginModule      - useful for test, this module can be configured to allow a static 
                             username and password, static username and any passowrd, or 
                             static password and any username
                             
    StaticRoleLoginModule  - this module performs no authentication, but can be configured to 
                             provide a static role for authenticated users.  This module is 
                             meant to be used in conjunction with password-stacking

    DebugLoginModule       - This module does no authentication or authorization, but will 
                             dump information about the jaas principle and roles known to 
                             the container.  This module is meant to be used in conjunction 
                             with password-stacking


System Requirements
-------------------

All you need to build this project is Java 6.0 (Java SDK 1.6) or better, Maven 3.0 or better.

The application this project produces is designed to be run on JBoss Enterprise Application Platform 6 or WildFly.


Configure Maven
---------------

If you have not yet done so, you must (http://www.jboss.org/jdf/quickstarts/jboss-as-quickstart/#configure_maven) before 
testing the quickstarts.


Configure JBoss
---------------

1. Open a command line and navigate to the root of the JBoss server directory.
2. The following shows the command line to start the server with the web profile:

        For Linux:   JBOSS_HOME/bin/standalone.sh
        For Windows: JBOSS_HOME\bin\standalone.bat

Build and deploy the login-modules
----------------------------------
_NOTE: The following build command assumes you have configured your Maven user settings. 


1. Open a command line and navigate to the root directory of this repo
2. Use this command to build the library:

    mvn clean install
    
3. Copy the resulting .jar file from ./target/login-modules-<version>.<version>.jar to the classpath of your EAP instance

Configure your EAP/WildFly instance to use the login-modules
------------------------------------------------------------


                        <login-module code="com.redhat.it.jboss.loginModules.JbossRadiusLoginModule" flag="required">
                            <module-option name="password-stacking" value="useFirstPass"/>
                            <module-option name="hostName" value="10.7.25.119"/>
                            <module-option name="secondaryHostName" value="10.7.25.124"/>
                            <module-option name="sharedSecret" value="redhat"/>
                            <module-option name="authRoleName" value="authenticated"/>
                            <module-option name="authPort" value="1812"/>
                            <module-option name="acctPort" value="1813"/>
                            <module-option name="numRetries" value="3"/>
                        </login-module>


Configure your web-app to use the new Security-Domain
-----------------------------------------------------

