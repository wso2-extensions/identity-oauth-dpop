/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.dpop.listener;

import java.text.ParseException;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.oauth2.authzChallenge.event.AuthzChallengeInterceptor;
import org.wso2.carbon.identity.oauth2.dpop.util.Utils;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthzChallengeReqDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.dpop.validators.DPoPHeaderValidator;

public class AuthzChallengeDPoPInterceptorHandlerProxy extends AbstractIdentityHandler implements
        AuthzChallengeInterceptor {

    private static final Log LOG = LogFactory.getLog(AuthzChallengeDPoPInterceptorHandlerProxy.class);
    private final DPoPHeaderValidator dPoPHeaderValidator;

    public AuthzChallengeDPoPInterceptorHandlerProxy(DPoPHeaderValidator dPoPHeaderValidator) {

        this.dPoPHeaderValidator = dPoPHeaderValidator;
    }

    /**
     * Handles the authorize-challenge request by validating the DPoP header.
     *
     * @param requestDTO authorize-challenge request DTO
     * @return thumbprint of the key extracted from the DPoP proof
     * @throws IdentityOAuth2Exception error during DPoP validation or parsing
     */
    @Override
    public String handleAuthzChallengeReq(OAuth2AuthzChallengeReqDTO requestDTO) throws IdentityOAuth2Exception {

        try {
            String dPoPProof = dPoPHeaderValidator.extractDPoPHeader(requestDTO.getHttpRequestHeaders());

            if (StringUtils.isBlank(dPoPProof)) {
                throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                        "DPoP header is required.");
            }

            String consumerKey = requestDTO.getClientId();
            HttpServletRequest request = requestDTO.getHttpServletRequestWrapper();
            String httpMethod = request.getMethod();
            String httpURL = request.getRequestURL().toString();
            if (!dPoPHeaderValidator.isValidDPoPProof(httpMethod, httpURL, dPoPProof)){
                if (LOG.isDebugEnabled()) {
                    LOG.debug(String.format("DPoP proof validation failed, Application ID: %s.", consumerKey));
                }
                throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                        DPoPConstants.INVALID_DPOP_ERROR);
            }
            return Utils.getThumbprintOfKeyFromDpopProof(dPoPProof);
        } catch (ParseException e) {
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                    "Error parsing DPoP proof header." , e);
        }
    }
}
