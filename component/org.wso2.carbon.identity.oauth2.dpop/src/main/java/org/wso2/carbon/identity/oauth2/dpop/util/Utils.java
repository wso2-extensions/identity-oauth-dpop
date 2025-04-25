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

package org.wso2.carbon.identity.oauth2.dpop.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils.isTableColumnExists;

/**
 * This class provides utility functions for dpop implementation.
 */
public class Utils {

    private static boolean isTenantIdColumnIsAvailableInIdnOidcAuthTable = false;
    private static Map<String, String> queries = new HashMap<>();

    public static JdbcTemplate getNewTemplate() {

        return new JdbcTemplate(IdentityDatabaseUtil.getDataSource());
    }

    /**
     * Get thumbprint value from the  jwk header parameter in the dpop proof.
     *
     * @param dPopProof DPoP proof header.
     * @return Thumbprint value.
     * @throws IdentityOAuth2Exception Error while getting the thumbprint value.
     */
    public static String getThumbprintOfKeyFromDpopProof(String dPopProof) throws IdentityOAuth2Exception {

        try {
            SignedJWT signedJwt = SignedJWT.parse(dPopProof);
            JWSHeader header = signedJwt.getHeader();
            return getKeyThumbprintOfKey(header.getJWK().toString(), signedJwt);
        } catch (ParseException | JOSEException e) {
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
    }

    private static String getKeyThumbprintOfKey(String jwk, SignedJWT signedJwt)
            throws ParseException, JOSEException {

        JWK parseJwk = JWK.parse(jwk);
        boolean validSignature;
        if (DPoPConstants.ECDSA_ENCRYPTION.equalsIgnoreCase(String.valueOf(parseJwk.getKeyType()))) {
            ECKey ecKey = (ECKey) parseJwk;
            ECPublicKey ecPublicKey = ecKey.toECPublicKey();
            validSignature = verifySignatureWithPublicKey(new ECDSAVerifier(ecPublicKey), signedJwt);
            if (validSignature) {
                return computeThumbprintOfECKey(ecKey);
            }
        } else if (DPoPConstants.RSA_ENCRYPTION.equalsIgnoreCase(String.valueOf(parseJwk.getKeyType()))) {
            RSAKey rsaKey = (RSAKey) parseJwk;
            RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
            validSignature = verifySignatureWithPublicKey(new RSASSAVerifier(rsaPublicKey), signedJwt);
            if (validSignature) {
                return computeThumbprintOfRSAKey(rsaKey);
            }
        }
        return StringUtils.EMPTY;
    }

    private static String computeThumbprintOfRSAKey(RSAKey rsaKey) throws JOSEException {

        return rsaKey.computeThumbprint().toString();
    }

    private static String computeThumbprintOfECKey(ECKey ecKey) throws JOSEException {

        return ecKey.computeThumbprint().toString();
    }

    private static boolean verifySignatureWithPublicKey(JWSVerifier jwsVerifier, SignedJWT signedJwt)
            throws JOSEException {

        return signedJwt.verify(jwsVerifier);
    }

    public static String getDBQuery(String key) {

        return queries.get(key);
    }

    public static boolean isTenantIdColumnAvailableInIdnOidcAuth() {

        return isTenantIdColumnIsAvailableInIdnOidcAuthTable;
    }

    /**
     * Checking whether the tenant id column is available in the IDN_OIDC_JTI table.
     */
    public static void checkIfTenantIdColumnIsAvailableInIdnOidcAuthTable() {

        isTenantIdColumnIsAvailableInIdnOidcAuthTable = isTableColumnExists(DPoPConstants.SQLQueries.IDN_OIDC_JTI,
                DPoPConstants.SQLQueries.TENANT_ID);
        buildQueryMapping();
    }

    private static void buildQueryMapping() {

        if (isTenantIdColumnIsAvailableInIdnOidcAuthTable) {
            queries.put(DPoPConstants.GET_JWT_ID, DPoPConstants.SQLQueries.GET_TENANTED_JWT_ID);
            queries.put(DPoPConstants.INSERT_JWD_ID, DPoPConstants.SQLQueries.INSERT_TENANTED_JWD_ID);
            queries.put(DPoPConstants.GET_JWT_DETAILS, DPoPConstants.SQLQueries.GET_JWT_DETAIL);
        } else {
            queries.put(DPoPConstants.GET_JWT_ID, DPoPConstants.SQLQueries.GET_JWT_ID);
            queries.put(DPoPConstants.GET_JWT, DPoPConstants.SQLQueries.GET_JWT);
            queries.put(DPoPConstants.INSERT_JWD_ID, DPoPConstants.SQLQueries.INSERT_JWD_ID);
        }
    }

}

