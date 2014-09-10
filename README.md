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
    
    StaticLoginModule      - useful for test, this module can be configured to allow a static username and password, 
                             static username and any passowrd, or static password and any username
                             
    StaticRoleLoginModule  - this module performs no authentication, but can be configured to provide a static role 
                             for authenticated users.  This module is meant to be used in conjunction with 
                             password-stacking

    DebugLoginModule       - This module does no authentication or authorization, but will dump information about 
                             the jaas principle and roles known to the container.  This module is meant to be used in
                             conjunction with password-stacking


System Requirements
-------------------

All you need to build this project is Java 6.0 (Java SDK 1.6) or better, Maven 3.0 or better.

The application this project produces is designed to be run on JBoss Enterprise Application Platform 6 or WildFly.


Configure Maven
---------------



Configure JBoss
---------------


