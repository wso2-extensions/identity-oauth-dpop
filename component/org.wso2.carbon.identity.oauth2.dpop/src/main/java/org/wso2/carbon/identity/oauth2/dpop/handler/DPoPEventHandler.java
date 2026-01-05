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
import org.wso2.carbon.identity.oauth2.dpop.util.Utils;
import org.wso2.carbon.identity.oauth2.dpop.validators.DPoPHeaderValidator;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;

import java.text.ParseException;
import java.util.Enumeration;
import java.util.Map;

import static org.wso2.carbon.identity.oauth.par.common.ParConstants.PRE_HANDLE_PAR_REQUEST;
import static org.wso2.carbon.identity.oauth.par.common.ParConstants.REQUEST_HEADERS;
import static org.wso2.carbon.identity.oauth.par.common.ParConstants.REQUEST_PARAMETERS;
import static org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants.DPOP_EVENT_HANDLER_NAME;
import static org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants.HTTP_POST;

/**
 * This class extends {@link AbstractEventHandler} and listen to oauth token related events.
 */
public class DPoPEventHandler extends AbstractEventHandler {

    private static final Log LOG = LogFactory.getLog(DPoPEventHandler.class);

    public String getName() {

        return DPOP_EVENT_HANDLER_NAME;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        if (StringUtils.equals(OIDCConstants.Event.POST_ISSUE_CODE, event.getEventName())) {

            // Get the code id and session data key from the event
            String codeId = event.getEventProperties().get(OIDCConstants.Event.CODE_ID).toString();
            String sessionDataKey = event.getEventProperties().get(OIDCConstants.Event.SESSION_DATA_KEY).toString();
            SessionDataCacheEntry sessionDataCacheEntry = SessionDataCache.getInstance()
                    .getValueFromCache(new SessionDataCacheKey(sessionDataKey));

            String clientId = sessionDataCacheEntry.getParamMap().get(DPoPConstants.CLIENT_ID)[0];
            try {
                DPoPHeaderValidator dPoPHeaderValidator = new DPoPHeaderValidator();
                String tokenBindingType = Utils.getApplicationBindingType(clientId, Utils.getTenantDomain());
                if (DPoPConstants.DPOP_TOKEN_TYPE.equals(tokenBindingType) &&
                        sessionDataCacheEntry.getParamMap().containsKey(DPoPConstants.DPOP_JKT)) {

                    String dpopJkt = sessionDataCacheEntry.getParamMap().get(DPoPConstants.DPOP_JKT)[0];
                    if (DPoPDataHolder.isDPoPJKTTableEnabled()) {
                        // Persist dpop_jkt in the DB
                        DPoPJKTDAOImpl dpopJKTDAO = new DPoPJKTDAOImpl();
                        dpopJKTDAO.insertDPoPJKT(clientId, codeId, dpopJkt);
                        // Persist dpop_jkt in the cache
                        if (DPoPJKTCache.getInstance().isEnabled()) {
                            DPoPJKTCacheKey dPoPJKTCacheKey = new DPoPJKTCacheKey(clientId,
                                    dpopJKTDAO.getAuthzCodeFromCodeId(codeId));
                            DPoPJKTCacheEntry dPoPJKTCacheEntry = new DPoPJKTCacheEntry(dpopJkt);
                            DPoPJKTCache.getInstance().addToCache(dPoPJKTCacheKey, dPoPJKTCacheEntry);
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("dpop_jkt was added to the cache for client id : " + clientId);
                            }
                        }
                    }
                }
            } catch (IdentityOAuth2Exception e) {
                LOG.error("Error while handling POST_ISSUE_CODE event for the client id : " + clientId, e);
                throw new IdentityEventException(e.getErrorCode(), e.getMessage());
            } catch (InvalidOAuthClientException e) {
                LOG.error("Client Authentication failed for the client id : " + clientId, e);
                throw new IdentityEventException(DPoPConstants.INVALID_CLIENT, DPoPConstants.INVALID_CLIENT_ERROR);
            }
        } else if (StringUtils.equals(PRE_HANDLE_PAR_REQUEST, event.getEventName())) {

            Map<String, Enumeration<String>> headers = (Map<String, Enumeration<String>>) event.getEventProperties()
                    .get(REQUEST_HEADERS);
            Map<String, String> parameters = (Map<String, String>) event.getEventProperties().get(REQUEST_PARAMETERS);
            String clientId = parameters.get(DPoPConstants.CLIENT_ID);
            try {
                DPoPHeaderValidator dPoPHeaderValidator = new DPoPHeaderValidator();
                String tokenBindingType = Utils.getApplicationBindingType(clientId, Utils.getTenantDomain());
                if (DPoPConstants.DPOP_TOKEN_TYPE.equals(tokenBindingType) &&
                        headers.containsKey(DPoPConstants.OAUTH_DPOP_HEADER.toLowerCase())) {
                    Enumeration<String> dPoPProofEnum = headers.get(DPoPConstants.OAUTH_DPOP_HEADER.toLowerCase());
                    String dPoPProof = dPoPProofEnum.nextElement();
                    if (dPoPProofEnum.hasMoreElements()) {
                        // More than one DPoP header is present in the request.
                        LOG.error("Invalid PAR request for the client id : " + clientId
                                + ". More than one DPoP header is present in the request.");
                        throw new IdentityEventException(DPoPConstants.INVALID_DPOP_PROOF,
                                DPoPConstants.INVALID_DPOP_ERROR);
                    }
                    if (dPoPHeaderValidator
                            .isValidDPoPProof(HTTP_POST, OAuth2Util.OAuthURL.getOAuth2ParEPUrl(), dPoPProof)) {
                        String thumbprint = Utils.getThumbprintOfKeyFromDpopProof(dPoPProof);
                        if (parameters.containsKey(DPoPConstants.DPOP_JKT)) {
                            String dpopJkt = parameters.get(DPoPConstants.DPOP_JKT);
                            if (!dpopJkt.equals(thumbprint)) {
                                throw new IdentityEventException(DPoPConstants.INVALID_DPOP_PROOF,
                                        DPoPConstants.INVALID_DPOP_ERROR);
                            }
                            return;
                        }
                        parameters.put(DPoPConstants.DPOP_JKT, thumbprint);
                    }
                }
            } catch (IdentityOAuth2Exception | ParseException e) {
                LOG.error("Error while handling PRE_HANDLE_PAR_REQUEST event for the client id : " + clientId, e);
                throw new IdentityEventException(DPoPConstants.INVALID_DPOP_PROOF, e.getMessage());
            } catch (InvalidOAuthClientException e) {
                LOG.error("Client Authentication failed for the client id : " + clientId, e);
                throw new IdentityEventException(DPoPConstants.INVALID_CLIENT, DPoPConstants.INVALID_CLIENT_ERROR);
            }
        }
    }
}
