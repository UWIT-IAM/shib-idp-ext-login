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

package edu.washington.shibboleth.config.profile.authn;

import edu.washington.shibboleth.authn.provider.UWLoginHandler;
import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerFactoryBean;

/**
 * Factory bean for {@link UWLoginHandler}s.
 */

public class UWLoginHandlerFactoryBean extends AbstractLoginHandlerFactoryBean{

    // plainAuthn servlet URL
    private String plainAuthnURL = null;

    // forceAuthn servlet URL
    private String forceAuthnURL = null;

    // passive servlet URL
    private String passiveAuthnURL = null;

    // token servlet URL
    private String tokenAuthnURL = null;

    // token30 servlet URL
    private String token30AuthnURL = null;

    // silver servlet URL
    private String silverAuthnURL = null;

    // sso session cookie name (for force)
    private String ssoCookieName = null;

    // file of list of auth token entity ids
    private String autoTokenAuthnURL = null;
    private String autoTokenFilename = null;

    // set and get the parameters

    public String getPlainAuthnURL(){
        return plainAuthnURL;
    }
    public void setPlainAuthnURL(String url){
        plainAuthnURL = url;
    }

    public String getForceAuthnURL(){
        return forceAuthnURL;
    }
    public void setForceAuthnURL(String url){
        forceAuthnURL = url;
    }

    public String getPassiveAuthnURL(){
        return passiveAuthnURL;
    }
    public void setPassiveAuthnURL(String url){
        passiveAuthnURL = url;
    }

    public String getTokenAuthnURL(){
        return tokenAuthnURL;
    }
    public void setTokenAuthnURL(String url){
        tokenAuthnURL = url;
    }

    public String getToken30AuthnURL(){
        return token30AuthnURL;
    }
    public void setToken30AuthnURL(String url){
        token30AuthnURL = url;
    }

    public String getSilverAuthnURL(){
        return silverAuthnURL;
    }
    public void setSilverAuthnURL(String url){
        silverAuthnURL = url;
    }

    public String getSsoCookieName(){
        return ssoCookieName;
    }
    public void setSsoCookieName(String name){
        ssoCookieName = name;
    }

    public String getAutoTokenAuthnURL(){
        return autoTokenAuthnURL;
    }
    public void setAutoTokenAuthnURL(String name){
        autoTokenAuthnURL = name;
    }

    public String getAutoTokenFilename(){
        return autoTokenFilename;
    }
    public void setAutoTokenFilename(String name){
        autoTokenFilename = name;
    }

    protected Object createInstance() throws Exception {
        UWLoginHandler handler = new UWLoginHandler(plainAuthnURL, forceAuthnURL, passiveAuthnURL, tokenAuthnURL, token30AuthnURL, silverAuthnURL, ssoCookieName, autoTokenAuthnURL, autoTokenFilename);
        populateHandler(handler);
        return handler;
    }

    public Class getObjectType() {
        return UWLoginHandler.class;
    }
}
