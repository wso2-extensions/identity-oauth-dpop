/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.dpop.dao;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.identity.oauth.tokenprocessor.HashingPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.dpop.util.Utils;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.JWTUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.TokenMgtUtil;

import java.util.List;
import java.util.Map;

/**
 * This class implements {@link DPoPTokenManagerDAO} interface.
 */
public class DPoPTokenManagerDAOImpl implements DPoPTokenManagerDAO {

    @Override
    public TokenBinding getTokenBindingUsingHash(String refreshToken)
            throws IdentityOAuth2Exception {

        if (refreshToken == null) {
            throw new IdentityOAuth2Exception("Refresh token cannot be null.");
        }
        if (JWTUtils.isJWT(refreshToken)) {
            return getTokenBindingFromRefreshTokenJWT(refreshToken);
        }

        JdbcTemplate jdbcTemplate = Utils.getNewTemplate();

        TokenPersistenceProcessor hashingPersistenceProcessor = new HashingPersistenceProcessor();
        refreshToken = hashingPersistenceProcessor.getProcessedRefreshToken(refreshToken);

        try {
            String finalRefreshToken = refreshToken;
            String retrieveTokenBindingQuery = OAuth2Util.isAccessTokenPersistenceEnabled() ?
                    SQLQueries.RETRIEVE_TOKEN_BINDING_BY_REFRESH_TOKEN_HASH :
                    SQLQueries.RETRIEVE_TOKEN_BINDING_BY_REFRESH_TOKEN_HASH_NON_PERSISTENT_ACCESS_TOKEN;
            List<TokenBinding> tokenBindingList = jdbcTemplate.executeQuery(
                    retrieveTokenBindingQuery,
                    (resultSet, rowNumber) -> {
                        TokenBinding tokenBinding = new TokenBinding();
                        tokenBinding.setBindingType(resultSet.getString(1));
                        tokenBinding.setBindingValue(resultSet.getString(2));
                        tokenBinding.setBindingReference(resultSet.getString(3));

                        return tokenBinding;
                    },
                    preparedStatement -> {
                        int parameterIndex = 0;
                        preparedStatement.setString(++parameterIndex, finalRefreshToken);
                        preparedStatement.setString(++parameterIndex, DPoPConstants.DPOP_TOKEN_TYPE);
                    });

            return tokenBindingList.isEmpty() ? null : tokenBindingList.get(0);
        } catch (DataAccessException e) {
            String error = String.format("Error obtaining token binding type using refresh token: %s.",
                    refreshToken);
            throw new IdentityOAuth2Exception(error, e);
        }
    }

    private TokenBinding getTokenBindingFromRefreshTokenJWT(String refreshToken) throws IdentityOAuth2Exception {

        SignedJWT signedJWT = TokenMgtUtil.parseJWT(refreshToken);
        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
        Object bindingTypeObj = claimsSet.getClaim("binding_type");
        Object bindingRefObj = claimsSet.getClaim("binding_ref");
        if (bindingTypeObj == null && bindingRefObj == null) {
            return null;
        }
        if (bindingTypeObj == null || bindingRefObj == null || StringUtils.isBlank(bindingRefObj.toString()) ||
                !DPoPConstants.DPOP_TOKEN_TYPE.equals(bindingTypeObj.toString())) {
            throw new IdentityOAuth2Exception("Malformed DPoP token binding claims found in the refresh token.");
        }

        TokenBinding tokenBinding = new TokenBinding();
        tokenBinding.setBindingType(bindingTypeObj.toString());
        tokenBinding.setBindingReference(bindingRefObj.toString());
        tokenBinding.setBindingValue(getDPoPBindingValue(claimsSet));
        return tokenBinding;
    }

    private String getDPoPBindingValue(JWTClaimsSet claimsSet) {

        Object cnfObj = claimsSet.getClaim(DPoPConstants.CNF);
        if (!(cnfObj instanceof Map)) {
            return null;
        }
        Object bindingValue = ((Map<?, ?>) cnfObj).get(DPoPConstants.JWK_THUMBPRINT);
        return bindingValue == null ? null : bindingValue.toString();
    }
}
