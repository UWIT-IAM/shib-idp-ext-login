/* ========================================================================
 * Copyright (c) 2009 The University of Washington
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
 * ========================================================================
 */

package edu.washington.shibboleth.authn.provider;

import java.io.IOException;
import java.util.Map;
import java.util.Enumeration;

import javax.servlet.ServletContext;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;


import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContextEntry;
import edu.internet2.middleware.shibboleth.idp.authn.PassiveAuthenticationException;


/**
 * Extracts the REMOTE_USER and places it in a request attribute to be used by the authentication engine.
 * Allows passive authn
 */
public class UWLoginServlet extends HttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = 1745454088856633626L;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(UWLoginServlet.class);

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        log.debug("UWLoginServlet init");
    }

    /** {@inheritDoc} */
    protected void service(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        log.debug("UWLoginServlet service");

        String principalName = httpRequest.getRemoteUser();

        if (principalName!=null) {
           log.debug("Remote user identified as {} returning control back to authentication engine", principalName);
           httpRequest.setAttribute(LoginHandler.PRINCIPAL_KEY, new UsernamePrincipal(principalName));
           AuthenticationEngine.returnToAuthenticationEngine(httpRequest, httpResponse);
        } else {
           log.debug("Passive remote user not available, returning control back to authentication engine");
           AuthenticationEngine.returnToAuthenticationEngine(httpRequest, httpResponse);

           // AuthenticationEngine.returnToProfileHandler(loginContext, httpRequest, httpResponse);
        }
    }
}
