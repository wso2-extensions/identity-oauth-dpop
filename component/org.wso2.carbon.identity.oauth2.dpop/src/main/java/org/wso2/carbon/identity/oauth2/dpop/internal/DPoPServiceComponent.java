/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.dpop.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.oauth.common.token.bindings.TokenBinderInfo;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IntrospectionDataProvider;
import org.wso2.carbon.identity.oauth2.dpop.dao.DPoPTokenManagerDAOImpl;
import org.wso2.carbon.identity.oauth2.dpop.handler.DPoPAuthenticationHandler;
import org.wso2.carbon.identity.oauth2.dpop.introspection.dataprovider.DPoPIntrospectionDataProvider;
import org.wso2.carbon.identity.oauth2.dpop.listener.OauthDPoPInterceptorHandlerProxy;
import org.wso2.carbon.identity.oauth2.dpop.token.binder.DPoPBasedTokenBinder;
import org.wso2.carbon.identity.oauth2.dpop.validators.DPoPTokenValidator;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidator;

/**
 * OSGi service component for DPoP.
 */
@Component(
        name = "org.wso2.carbon.identity.oauth2.dpop",
        immediate = true)
public class DPoPServiceComponent {

    private static final Log log = LogFactory.getLog(DPoPServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            DPoPDataHolder.getInstance().setTokenBindingTypeManagerDao(new DPoPTokenManagerDAOImpl());
            context.getBundleContext().registerService(TokenBinderInfo.class.getName(),
                    new DPoPBasedTokenBinder(), null);
            context.getBundleContext().registerService(OAuthEventInterceptor.class,
                    new OauthDPoPInterceptorHandlerProxy(), null);
            context.getBundleContext().registerService(AuthenticationHandler.class.getName(),
                    new DPoPAuthenticationHandler(), null);
            context.getBundleContext().registerService(IntrospectionDataProvider.class.getName(),
                    new DPoPIntrospectionDataProvider(), null);
            context.getBundleContext().registerService(OAuth2TokenValidator.class.getName(),
                    new DPoPTokenValidator(), null);
            if (log.isDebugEnabled()) {
                log.debug("DPoPService is activated.");
            }
        } catch (Throwable e) {
            log.error("Error while activating DPoPServiceComponent.", e);
        }
    }
}
