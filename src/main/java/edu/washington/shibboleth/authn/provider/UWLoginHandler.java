/* ========================================================================
 * Copyright (c) 2009-2013 The University of Washington
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

import java.util.Date;
import java.io.File;
import java.util.Vector;
import java.io.IOException;
import java.util.List;
import java.util.Iterator;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.ServletContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.opensaml.util.URLBuilder;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.util.storage.StorageService;

import edu.internet2.middleware.shibboleth.idp.authn.provider.AbstractLoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.ShibbolethSSOLoginContext;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

public class UWLoginHandler extends AbstractLoginHandler {

    private final Logger log = LoggerFactory.getLogger(UWLoginHandler.class);

    public static final String UW_LOGIN_SILVER_AUTHN_METHOD = "http://incommonfederation.org/assurance/silver";
    public static final String UW_LOGIN_SILVER_TEST_AUTHN_METHOD = "http://incommonfederation.org/assurance/silver-test";

    // URL redirects to the weblogin handlers

    // plainAuthn servlet URL
    private String plainAuthnURL;

    // forceAuthn servlet URL
    private String forceAuthnURL;

    // passive servlet URL
    private String passiveAuthnURL;

    // token servlet URL
    private String tokenAuthnURL;

    // token-30 servlet URL
    private String token30AuthnURL;

    // silver servlet URL
    private String silverAuthnURL;

    // auto token URL
    private String autoTokenAuthnURL;

    // sso session cookie name
    private String ssoCookieName;

    // list of auto token entity ids
    private String autoTokenEntityFilename;
    private List<String> autoTokenEntities;
    private long ateModified = 0;
    private long ateChecked = 0;
    private long atePoll = 600;  // ten minutes
    public void setAtePoll(long v) {
       atePoll = v;
    }


    /**
     * Constructor.
     *
     * @param URLs to the authentication servlets
     */
   public UWLoginHandler(String plain, String force, String passive, String token, String token30, String silver, String cookie, String autourl, String autotokfile) {
        super();
        log.debug("UWLoginHandler constructor");
        plainAuthnURL = plain;
        forceAuthnURL = force;
        passiveAuthnURL = passive;
        tokenAuthnURL = token;
        token30AuthnURL = token30;
        silverAuthnURL = silver;
        ssoCookieName = cookie;
        setSupportsPassive(true);
        setSupportsForceAuthentication(true);

        // configure auto token entityids
        autoTokenAuthnURL = autourl;
        autoTokenEntityFilename = autotokfile;
        autoTokenEntities = null;
        refreshAuthTokenEntities();
    }

   // check the autoproxy file for changes
   public void refreshAuthTokenEntities() {

      if (autoTokenEntityFilename==null) return;  // no file

      Date nowDate = new Date();
      long now = nowDate.getTime();
      if (now < ( ateChecked + atePoll ) ) return;

      try {
         File af = new File(autoTokenEntityFilename);
         if (ateModified < af.lastModified()) {
            log.debug("refreshing autotokens from: " + autoTokenEntityFilename);
            ateModified = af.lastModified();
            List<String> newAutoToks = new Vector<String>();

            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(af);
            doc.getDocumentElement().normalize();

            NodeList rpNodes = doc.getElementsByTagName("AutoToken");

            for (int i=0; i<rpNodes.getLength(); i++) {
               Node rpNode = rpNodes.item(i);
               if (rpNode.getNodeType() == Node.ELEMENT_NODE) {
                  String rp = ((Element)rpNode).getAttribute("entityId");
                  if (rp.length()>0) newAutoToks.add(rp);
                  log.debug("adding autotok: " + rp);
               }
            }
            autoTokenEntities = newAutoToks;
         }

      } catch (IOException e) {
         log.error("could not read autotok file: " + e);
      } catch (ParserConfigurationException e) {
         log.error("parse config autotok file: " + e);
      } catch (SAXException e) {
         log.error("could not parse autotok file: " + e);
      }
      ateChecked = now;
   }



    public void login(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse) {

        log.debug("UWLogin login");
        boolean needAutoTok = false;

        // shib 2.0 way
        // LoginContext loginContext = (LoginContext) httpRequest.getAttribute(LoginContext.LOGIN_CONTEXT_KEY);
        // shib 2.2.0-snap way
        // LoginContext loginContext = HttpServletHelper.getLoginContext(httpRequest);
        // shib 2.2.0 way
        ServletContext context = httpRequest.getSession().getServletContext();
        LoginContext loginContext = HttpServletHelper.getLoginContext(HttpServletHelper.getStorageService(context), context, httpRequest);
        
        if (loginContext==null) {
           log.error("No login context!? Unable to redirect to authentication servlet.");
           return;
        }
        String attemptedMethod = loginContext.getAttemptedAuthnMethod();
        log.debug(".. attempting: " + attemptedMethod);

        String authnURL = plainAuthnURL;
        String authnMethod = AuthnContext.PPT_AUTHN_CTX;

        // check auto token upgrades
        if (autoTokenEntities!=null && autoTokenEntities.size()>0 && !attemptedMethod.equals(AuthnContext.TIME_SYNC_TOKEN_AUTHN_CTX)) {
           String rpId = loginContext.getRelyingPartyId();
           log.debug("checking {} for autotok", rpId);
           for (int i=0; i<autoTokenEntities.size(); i++) {
              if (autoTokenEntities.get(i).equals(rpId)) {
                  needAutoTok = true;
                  log.debug("is active autotok");
                  break;
              }
           }
        }

        if (needAutoTok || loginContext.isForceAuthRequired()) {
           authnURL = forceAuthnURL;
           log.debug("uwlogin: forceAuthn, sso cookie=" + ssoCookieName);

           // need to clear weblogin's session cookies
           Cookie[] cookies = httpRequest.getCookies();
           if (cookies != null && ssoCookieName != null) {
                for (Cookie cookie : cookies) {
                    if (cookie.getName().matches(ssoCookieName)) {
                        log.debug(" uwlogin:  clearing session cookie:" + cookie.getName());
                        Cookie voidCookie = new Cookie(cookie.getName(), "");
                        voidCookie.setMaxAge(0);
                        voidCookie.setPath("/");    // cookie path should be config?
                        voidCookie.setSecure(true);
                        httpResponse.addCookie(voidCookie);
                    }
                }
            }
        }

        if (loginContext.isPassiveAuthRequired()) {
           authnURL = passiveAuthnURL;
           log.debug("uwlogin:  passive requested");
        }

        if (attemptedMethod.equals(UW_LOGIN_SILVER_AUTHN_METHOD)) {
           log.debug("uwlogin:  is silver");  
           authnURL = silverAuthnURL;
           authnMethod = UW_LOGIN_SILVER_AUTHN_METHOD;

        } else if (attemptedMethod.equals(UW_LOGIN_SILVER_TEST_AUTHN_METHOD)) {
           log.debug("uwlogin:  is silver test");  
           authnURL = silverAuthnURL;
           authnMethod = UW_LOGIN_SILVER_TEST_AUTHN_METHOD;

        } else if (attemptedMethod.equals(AuthnContext.TIME_SYNC_TOKEN_AUTHN_CTX)) {
           if (authnURL==plainAuthnURL) {
              authnURL = token30AuthnURL;
              log.debug("uwlogin:  is securid 30 (without reauth)");
           } else {
              authnURL = tokenAuthnURL;
              log.debug("uwlogin:  is securid (reauth)");
           }
           authnMethod = AuthnContext.TIME_SYNC_TOKEN_AUTHN_CTX;

        } else if (attemptedMethod.equals(AuthnContext.PASSWORD_AUTHN_CTX)) {
           authnMethod = AuthnContext.PASSWORD_AUTHN_CTX;
        }
        if (needAutoTok) {
           authnURL = autoTokenAuthnURL;
        }


        // log.debug("uwlogin:  url: " + authnURL + ", authnMethod: " + authnMethod);
        httpRequest.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, authnMethod);

        // forward control to the servlet
        try {
            StringBuilder pathBuilder = new StringBuilder();
            pathBuilder.append(httpRequest.getContextPath());
            if(!authnURL.startsWith("/")){
                pathBuilder.append("/");
            }

            pathBuilder.append(authnURL);

            URLBuilder urlBuilder = new URLBuilder();
            urlBuilder.setScheme(httpRequest.getScheme());
            urlBuilder.setHost(httpRequest.getServerName());
            urlBuilder.setPort(httpRequest.getServerPort());
            urlBuilder.setPath(pathBuilder.toString());

            log.debug("Redirecting to {}", urlBuilder.buildURL());
            httpResponse.sendRedirect(urlBuilder.buildURL());
            return;

        } catch (IOException ex) {
            log.error("Unable to redirect to authentication servlet.", ex);
        }
    }
}
