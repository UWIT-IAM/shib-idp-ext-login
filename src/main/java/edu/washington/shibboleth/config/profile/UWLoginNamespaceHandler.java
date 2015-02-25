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

package edu.washington.shibboleth.config.profile;

import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

import edu.washington.shibboleth.config.profile.authn.UWLoginHandlerBeanDefinitionParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class UWLoginNamespaceHandler extends BaseSpringNamespaceHandler {

     /** Namespace URI. */
    public static final String NAMESPACE = "urn:mace:washington.edu:shibboleth:2.0:authn";
   /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(UWLoginNamespaceHandler.class);


    public void init(){
        // super.init();
        log.debug("UWLoginNamespaceHandler registering " + UWLoginHandlerBeanDefinitionParser.SCHEMA_TYPE.toString());

        registerBeanDefinitionParser(UWLoginHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new UWLoginHandlerBeanDefinitionParser());
    }
}
