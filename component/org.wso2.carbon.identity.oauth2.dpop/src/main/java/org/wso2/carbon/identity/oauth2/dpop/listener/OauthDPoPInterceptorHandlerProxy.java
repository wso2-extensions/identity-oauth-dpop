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

package org.wso2.carbon.identity.oauth2.dpop.listener;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.dpop.dao.DPoPTokenManagerDAO;
import org.wso2.carbon.identity.oauth2.dpop.internal.DPoPDataHolder;
import org.wso2.carbon.identity.oauth2.dpop.validators.DPoPHeaderValidator;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Map;

/**
 * This class extends {@link AbstractOAuthEventInterceptor} and listen to oauth token related events.
 * In this class, DPoP proof validation will be handled for DPoP token requests.
 */
public class OauthDPoPInterceptorHandlerProxy extends AbstractOAuthEventInterceptor {

    private static final Log LOG = LogFactory.getLog(OauthDPoPInterceptorHandlerProxy.class);
    private final DPoPTokenManagerDAO tokenBindingTypeManagerDao = DPoPDataHolder.getInstance()
            .getTokenBindingTypeManagerDao();
    private final DPoPHeaderValidator dPoPHeaderValidator;

    public OauthDPoPInterceptorHandlerProxy(DPoPHeaderValidator dPoPHeaderValidator) {

        this.dPoPHeaderValidator = dPoPHeaderValidator;
    }

    /**
     * {@inheritdoc}
     */
    @Override
    public void onPreTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                Map<String, Object> params) throws IdentityOAuth2Exception {

        String consumerKey = tokenReqDTO.getClientId();
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("DPoP proxy intercepted the token request from the client : %s.", consumerKey));
        }
        try {
            String tokenBindingType = dPoPHeaderValidator.getApplicationBindingType(tokenReqDTO.getClientId());
            if (DPoPConstants.DPOP_TOKEN_TYPE.equals(tokenBindingType)) {

                String dPoPProof = dPoPHeaderValidator.getDPoPHeader(tokReqMsgCtx);
                if (StringUtils.isBlank(dPoPProof)) {
                    throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                            "DPoP header is required.");
                }
                boolean isValidDPoP = dPoPHeaderValidator.isValidDPoP(dPoPProof, tokenReqDTO, tokReqMsgCtx);
                if (!isValidDPoP) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(String.format("DPoP proof validation failed, Application ID: %s.", consumerKey));
                    }
                    throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                            DPoPConstants.INVALID_DPOP_ERROR);
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(String.format("Bearer access token request received from client: %s.", consumerKey));
                }
            }
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_CLIENT, DPoPConstants.INVALID_CLIENT_ERROR);
        }
    }

    /**
     * {@inheritdoc}
     */
    @Override
    public void onPreTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                  Map<String, Object> params) throws IdentityOAuth2Exception {

        String consumerKey = tokenReqDTO.getClientId();
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("DPoP proxy intercepted the token renewal request from the client : %s.",
                    consumerKey));
        }
        try {
            String tokenBindingType = dPoPHeaderValidator.getApplicationBindingType(tokenReqDTO.getClientId());
            TokenBinding tokenBinding = tokenBindingTypeManagerDao.getTokenBinding(tokenReqDTO.getRefreshToken(),
                            OAuth2Util.isHashEnabled());
            if (tokenBinding != null) {
                if (!DPoPConstants.DPOP_TOKEN_TYPE.equals(tokenBindingType)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(String.format("DPoP based token binding is not enabled  for the " +
                                "application Id : %s.", consumerKey));
                    }
                    throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_CLIENT,
                            DPoPConstants.INVALID_CLIENT_ERROR);
                }

                String dPoPProof = dPoPHeaderValidator.getDPoPHeader(tokReqMsgCtx);
                if (StringUtils.isBlank(dPoPProof)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(String.format("Renewal request received without the DPoP proof from the " +
                                "application Id: %s.", consumerKey));
                    }
                    throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                            "DPoP proof is required.");
                }

                if (!dPoPHeaderValidator.isValidDPoP(dPoPProof, tokenReqDTO, tokReqMsgCtx)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(String.format("DPoP proof validation failed for the application Id : %s.",
                                consumerKey));
                    }
                    throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                            DPoPConstants.INVALID_DPOP_ERROR);
                }
                if (!tokReqMsgCtx.getTokenBinding().getBindingValue()
                        .equalsIgnoreCase(tokenBinding.getBindingValue())) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("DPoP proof thumbprint value of the public key is not equal to binding value from" +
                                " the refresh token.");
                    }
                    throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                            DPoPConstants.INVALID_DPOP_ERROR);
                }
            }
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_CLIENT, DPoPConstants.INVALID_CLIENT_ERROR);
        }
    }

    @Override
    public boolean isEnabled() {

        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.readEventListenerProperty
                (AbstractIdentityHandler.class.getName(), this.getClass().getName());
        return identityEventListenerConfig != null && Boolean.parseBoolean(identityEventListenerConfig.getEnable());
    }

    /**
     * {@inheritdoc}
     */
    @Override
    public void onPostTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                 OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params) {

        setDPoPTokenType(tokReqMsgCtx, tokenRespDTO);
    }

    /**
     * {@inheritdoc}
     */
    @Override
    public void onPostTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                   OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params) {

        setDPoPTokenType(tokReqMsgCtx, tokenRespDTO);

    }

    private void setDPoPTokenType(OAuthTokenReqMessageContext tokReqMsgCtx, OAuth2AccessTokenRespDTO tokenRespDTO) {

        if (tokReqMsgCtx.getTokenBinding() != null &&
                DPoPConstants.DPOP_TOKEN_TYPE.equals(tokReqMsgCtx.getTokenBinding().getBindingType())) {
            if (tokenRespDTO != null) {
                tokenRespDTO.setTokenType(DPoPConstants.DPOP_TOKEN_TYPE);
            }
        }
    }
}
