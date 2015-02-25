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

import javax.xml.namespace.QName;

import org.opensaml.xml.util.DatatypeHelper;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerBeanDefinitionParser;

import edu.washington.shibboleth.config.profile.UWLoginNamespaceHandler;

public class UWLoginHandlerBeanDefinitionParser extends AbstractLoginHandlerBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(UWLoginNamespaceHandler.NAMESPACE, "UWLogin");

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(UWLoginHandlerBeanDefinitionParser.class);

    /** {@inheritDoc} */
    protected Class getBeanClass(Element element) {
        return UWLoginHandlerFactoryBean.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        super.doParse(config, builder);
        log.debug("uwlogin: forceA = " + DatatypeHelper.safeTrim(config.getAttributeNS(null,"forceAuthnURL")));
        builder.addPropertyValue("plainAuthnURL", DatatypeHelper.safeTrim(config.getAttributeNS(null,"plainAuthnURL")));
        builder.addPropertyValue("forceAuthnURL", DatatypeHelper.safeTrim(config.getAttributeNS(null,"forceAuthnURL")));
        builder.addPropertyValue("passiveAuthnURL", DatatypeHelper.safeTrim(config.getAttributeNS(null,"passiveAuthnURL")));
        builder.addPropertyValue("tokenAuthnURL", DatatypeHelper.safeTrim(config.getAttributeNS(null,"tokenAuthnURL")));
        builder.addPropertyValue("token30AuthnURL", DatatypeHelper.safeTrim(config.getAttributeNS(null,"token30AuthnURL")));
        builder.addPropertyValue("silverAuthnURL", DatatypeHelper.safeTrim(config.getAttributeNS(null,"silverAuthnURL")));
        builder.addPropertyValue("autoTokenAuthnURL", DatatypeHelper.safeTrim(config.getAttributeNS(null,"autoTokenAuthnURL")));
        builder.addPropertyValue("autoTokenFilename", DatatypeHelper.safeTrim(config.getAttributeNS(null,"autoTokenFilename")));
        builder.addPropertyValue("ssoCookieName", DatatypeHelper.safeTrim(config.getAttributeNS(null,"ssoCookieName")));

        /*** omitted.  don't remember why this was here. 
        String jaasConfigurationURL = DatatypeHelper.safeTrim(config.getAttributeNS(null, "jaasConfigurationLocation"));
        log.debug("Setting JAAS configuration file to: {}", jaasConfigurationURL);
        System.setProperty("java.security.auth.login.config", jaasConfigurationURL);
        **/
    }
}

