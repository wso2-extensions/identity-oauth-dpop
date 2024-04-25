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

package org.wso2.carbon.identity.oauth2.dpop.handler;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dpop.cache.DPoPJKTCache;
import org.wso2.carbon.identity.oauth2.dpop.cache.DPoPJKTCacheEntry;
import org.wso2.carbon.identity.oauth2.dpop.cache.DPoPJKTCacheKey;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.dpop.dao.DPoPJKTDAOImpl;
import org.wso2.carbon.identity.oauth2.dpop.internal.DPoPDataHolder;
import org.wso2.carbon.identity.oauth2.dpop.validators.DPoPHeaderValidator;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;

/**
 * This class extends {@link AbstractEventHandler} and listen to oauth token related events.
 */
public class DPoPEventHandler extends AbstractEventHandler {

    private static final Log LOG = LogFactory.getLog(DPoPEventHandler.class);

    public String getName() {

        return "dpopEventHandler";
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        if (StringUtils.equals(OIDCConstants.Event.POST_ISSUE_CODE, event.getEventName())) {

            String codeId  = event.getEventProperties().get(OIDCConstants.Event.CODE_ID).toString();
            String sessionDataKey = event.getEventProperties().get(OIDCConstants.Event.SESSION_DATA_KEY).toString();
            SessionDataCacheEntry sessionDataCacheEntry = SessionDataCache.getInstance()
                    .getValueFromCache(new SessionDataCacheKey(sessionDataKey));

            if (sessionDataCacheEntry.getParamMap().containsKey(DPoPConstants.DPOP_JKT)) {
                String dpopJkt = sessionDataCacheEntry.getParamMap().get(DPoPConstants.DPOP_JKT)[0];
                String consumerKey = sessionDataCacheEntry.getParamMap().get(DPoPConstants.CLIENT_ID)[0];
                try {
                    DPoPHeaderValidator dPoPHeaderValidator = new DPoPHeaderValidator();
                    String tokenBindingType = dPoPHeaderValidator.getApplicationBindingType(consumerKey);

                    if (DPoPConstants.DPOP_TOKEN_TYPE.equals(tokenBindingType) &&
                            DPoPDataHolder.isDPoPJKTTableEnabled()) {

                        // Persist dpop_jkt in the DB
                        DPoPJKTDAOImpl dpopJKTDAO = new DPoPJKTDAOImpl();
                        dpopJKTDAO.insertDPoPJKT(consumerKey, codeId, dpopJkt);
                        // Persist dpop_jkt in the cache
                        if (OAuthCache.getInstance().isEnabled()) {
                            DPoPJKTCacheKey dPoPJKTCacheKey = new DPoPJKTCacheKey(consumerKey,
                                    dpopJKTDAO.getAuthzCodeFromCodeId(codeId));
                            DPoPJKTCacheEntry dPoPJKTCacheEntry = new DPoPJKTCacheEntry(dpopJkt);
                            DPoPJKTCache.getInstance().addToCache(dPoPJKTCacheKey, dPoPJKTCacheEntry);
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("dpop_jkt was added to the cache for client id : " +
                                        consumerKey);
                            }
                        }
                    }
                } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
                    LOG.error("Error while persisting dpop_jkt for the client id : " + consumerKey, e);
                    throw new IdentityEventException(DPoPConstants.INVALID_CLIENT, DPoPConstants.INVALID_CLIENT_ERROR);
                }
            }
        }
    }
}
