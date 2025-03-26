/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.dpop.validators;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dpop.cache.DPoPJKTCache;
import org.wso2.carbon.identity.oauth2.dpop.cache.DPoPJKTCacheEntry;
import org.wso2.carbon.identity.oauth2.dpop.cache.DPoPJKTCacheKey;
import org.wso2.carbon.identity.oauth2.dpop.cache.DPoPJTICache;
import org.wso2.carbon.identity.oauth2.dpop.cache.DPoPJTICacheEntry;
import org.wso2.carbon.identity.oauth2.dpop.cache.DPoPJTICacheKey;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.dpop.dao.DPoPJKTDAOImpl;
import org.wso2.carbon.identity.oauth2.dpop.dao.JWTEntry;
import org.wso2.carbon.identity.oauth2.dpop.dao.JWTStorageManager;
import org.wso2.carbon.identity.oauth2.dpop.internal.DPoPDataHolder;
import org.wso2.carbon.identity.oauth2.dpop.listener.OauthDPoPInterceptorHandlerProxy;
import org.wso2.carbon.identity.oauth2.dpop.util.Utils;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

/**
 * DPoP Header  validator.
 */
public class DPoPHeaderValidator {

    private final JWTStorageManager jwtStorageManager;

    private static final Log LOG = LogFactory.getLog(DPoPHeaderValidator.class);

    public DPoPHeaderValidator() {
        this.jwtStorageManager = new JWTStorageManager();
    }

    /**
     * Extract DPoP header from the headers.
     *
     * @param tokReqMsgCtx Message context of token request.
     * @return DPoP header.
     */
    public String getDPoPHeader(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2ClientException {

        HttpRequestHeader[] httpRequestHeaders = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getHttpRequestHeaders();
        if (httpRequestHeaders != null) {
            for (HttpRequestHeader header : httpRequestHeaders) {
                if (header != null && DPoPConstants.OAUTH_DPOP_HEADER.equalsIgnoreCase(header.getName())) {
                    if (ArrayUtils.isNotEmpty(header.getValue())) {
                        if (header.getValue().length > 1) {
                            String error = "Exception occurred while extracting the DPoP proof header: " +
                                    "Request contains multiple DPoP headers.";
                            LOG.error(error);
                            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, error);
                        }
                        return header.getValue()[0];
                    }
                    return null;
                }
            }
        }
        return StringUtils.EMPTY;
    }

    /**
     * Get Oauth application Access token binding type.
     *
     * @param consumerKey Consumer Key.
     * @return Access token binding type of the oauth application.
     * @throws InvalidOAuthClientException Error while getting the Oauth application information.
     * @throws IdentityOAuth2Exception Error while getting the Oauth application information.
     */
    public String getApplicationBindingType(String consumerKey) throws
            IdentityOAuth2Exception, InvalidOAuthClientException {

        OAuthAppDO oauthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        return oauthAppDO.getTokenBindingType();
    }

    /**
     * Validate dpop proof header.
     *
     * @param httpMethod HTTP method of the request.
     * @param httpURL HTTP URL of the request,
     * @param dPoPProof DPoP header of the request.
     * @return
     * @throws ParseException Error while retrieving the signedJwt.
     * @throws IdentityOAuth2Exception Error while validating the dpop proof.
     */
    public boolean isValidDPoPProof(String httpMethod, String httpURL, String dPoPProof)
            throws ParseException, IdentityOAuth2Exception {

        SignedJWT signedJwt = SignedJWT.parse(dPoPProof);
        JWSHeader header = signedJwt.getHeader();

        return validateDPoPPayload(httpMethod, httpURL, signedJwt.getJWTClaimsSet()) && validateDPoPHeader(header);
    }

    /**
     * Validate dpop proof header.
     *
     * @param httpMethod HTTP method of the request.
     * @param httpURL HTTP URL of the request,
     * @param dPoPProof DPoP header of the request.
     * @param token Access token / Refresh token.
     * @return
     * @throws ParseException Error while retrieving the signedJwt.
     * @throws IdentityOAuth2Exception Error while validating the dpop proof.
     */
    public boolean isValidDPoPProof(String httpMethod, String httpURL, String dPoPProof, String token)
            throws ParseException, IdentityOAuth2Exception  {

        SignedJWT signedJwt = SignedJWT.parse(dPoPProof);
        JWSHeader header = signedJwt.getHeader();

        return validateDPoPPayload(httpMethod, httpURL, signedJwt.getJWTClaimsSet(), token) &&
                validateDPoPHeader(header);
    }

    /**
     * Set token binder information if dpop proof is valid.
     *
     * @param dPoPProof DPoP proof header.
     * @param tokenReqDTO Token request dto.
     * @param tokReqMsgCtx Message context of token request.
     * @return
     * @throws IdentityOAuth2Exception Error while validating the dpop proof.
     */
    public boolean isValidDPoP(String dPoPProof, OAuth2AccessTokenReqDTO tokenReqDTO,
            OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        try {
            HttpServletRequest request = tokenReqDTO.getHttpServletRequestWrapper();
            String httpMethod = request.getMethod();
            String httpURI = request.getRequestURI();
            String httpURL = OAuth2Util.buildServiceUrl(httpURI, null, null);
            
            if (isValidDPoPProof(httpMethod, httpURL, dPoPProof)) {
                String thumbprint = Utils.getThumbprintOfKeyFromDpopProof(dPoPProof);
                if (StringUtils.isNotBlank(thumbprint)) {
                    if (DPoPDataHolder.isDPoPJKTTableEnabled()) {
                        validateDPoPJKT(tokenReqDTO, thumbprint);
                    }
                    TokenBinding tokenBinding = new TokenBinding();
                    tokenBinding.setBindingType(DPoPConstants.DPOP_TOKEN_TYPE);
                    tokenBinding.setBindingValue(thumbprint);
                    tokenBinding.setBindingReference(DigestUtils.md5Hex(thumbprint));
                    tokReqMsgCtx.setTokenBinding(tokenBinding);
                    setCnFValue(tokReqMsgCtx, tokenBinding.getBindingValue());
                    return true;
                }
            }
        } catch (ParseException e) {
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
        return false;
    }

    private boolean validateDPoPHeader(JWSHeader header) throws IdentityOAuth2Exception {

        return checkJwk(header) && checkAlg(header) && checkHeaderType(header);
    }

    //Authorization server side validator without "ath" claim validation
    private boolean validateDPoPPayload(String httpMethod, String httpURL, JWTClaimsSet jwtClaimsSet)
            throws IdentityOAuth2Exception {

        return checkJwtClaimSet(jwtClaimsSet) && checkDPoPHeaderValidity(jwtClaimsSet) && checkJti(jwtClaimsSet) &&
                checkHTTPMethod(httpMethod, jwtClaimsSet) && checkHTTPURI(httpURL, jwtClaimsSet);
    }

    //Resource server side validator with "ath" claim validation
    private boolean validateDPoPPayload(String httpMethod, String httpURL, JWTClaimsSet jwtClaimsSet,
                                               String token) throws IdentityOAuth2Exception {

        return checkJwtClaimSet(jwtClaimsSet) && checkDPoPHeaderValidity(jwtClaimsSet) && checkJti(jwtClaimsSet) &&
                checkHTTPMethod(httpMethod, jwtClaimsSet) && checkHTTPURI(httpURL, jwtClaimsSet) &&
                checkAth(token, jwtClaimsSet);
    }

    private boolean checkJwk(JWSHeader header) throws IdentityOAuth2ClientException {

        JWK jwk = header.getJWK();
        if (jwk != null) {
            if (!header.getJWK().isPrivate()) {
                return true;
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Private key is used in the DPoP Proof header.");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("'jwk' is not presented in the DPoP Proof header");
        }
        throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
    }

    private boolean checkAlg(JWSHeader header) throws IdentityOAuth2ClientException {

        JWSAlgorithm algorithm = header.getAlgorithm();
        if (algorithm == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("'algorithm' is not presented in the DPoP Proof header");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
        return true;
    }

    private boolean checkHeaderType(JWSHeader header) throws IdentityOAuth2ClientException {

        if (!DPoPConstants.DPOP_JWT_TYPE.equalsIgnoreCase(header.getType().toString())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(" typ field value in the DPoP Proof header  is not equal to 'dpop+jwt'");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
        return true;
    }

    private boolean checkJwtClaimSet(JWTClaimsSet jwtClaimsSet) throws IdentityOAuth2ClientException {

        if (jwtClaimsSet == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("'jwtClaimsSet' is missing in the body of a DPoP proof.");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
        return true;
    }

    private boolean checkDPoPHeaderValidity(JWTClaimsSet jwtClaimsSet) throws IdentityOAuth2ClientException {

        Timestamp currentTimestamp = new Timestamp(new Date().getTime());
        Date issuedAt = (Date) jwtClaimsSet.getClaim(DPoPConstants.DPOP_ISSUED_AT);
        if (issuedAt == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("DPoP Proof missing the 'iat' field.");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
        boolean isExpired = (currentTimestamp.getTime() - issuedAt.getTime()) > getDPoPValidityPeriod();
        if (isExpired) {
            String error = "Expired DPoP Proof";
            if (LOG.isDebugEnabled()) {
                LOG.debug(error);
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, error);
        }
        return true;
    }

    private boolean checkJti(JWTClaimsSet jwtClaimsSet)
            throws IdentityOAuth2Exception {

        if (!jwtClaimsSet.getClaims().containsKey(DPoPConstants.JTI)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("'jti' is missing in the 'jwtClaimsSet' of the DPoP proof body.");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }

        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        int tenantId = carbonContext.getTenantId();

        Date expirationTime = jwtClaimsSet.getExpirationTime();
        Date issuedAtTime = jwtClaimsSet.getIssueTime();

        long expTime = 0;
        long issuedTime = 0;

        if (expirationTime != null) {
            expTime = expirationTime.getTime();
        }
        if (issuedAtTime != null) {
            issuedTime = issuedAtTime.getTime();
        }

        String jti;
        try {
            jti = jwtClaimsSet.getStringClaim(DPoPConstants.JTI);
        } catch (ParseException e) {
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }

        isJTIReplay(jti, tenantId);
        persistJWTID(jti, expTime, issuedTime, tenantId);

        return true;
    }

    private boolean checkHTTPMethod(String httpMethod, JWTClaimsSet jwtClaimsSet)
            throws IdentityOAuth2ClientException {

        Object dPoPHttpMethod = jwtClaimsSet.getClaim(DPoPConstants.DPOP_HTTP_METHOD);

        // Check if the DPoP proof HTTP method is empty.
        if (dPoPHttpMethod == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("DPoP Proof HTTP method empty.");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }

        // Validate if the DPoP proof HTTP method matches that of the request.
        if (!httpMethod.equalsIgnoreCase(dPoPHttpMethod.toString())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("DPoP Proof HTTP method mismatch.");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
        return true;
    }

    private boolean checkHTTPURI(String httpUrl, JWTClaimsSet jwtClaimsSet)
            throws IdentityOAuth2ClientException {

        Object dPoPContextPath = jwtClaimsSet.getClaim(DPoPConstants.DPOP_HTTP_URI);

        if (dPoPContextPath == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("DPoP Proof context path empty.");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }

        // Validate if the DPoP proof HTTP URI matches that of the request.
        if (!httpUrl.equalsIgnoreCase(dPoPContextPath.toString())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("DPoP Proof context path mismatch.");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
        return true;
    }

    private int getDPoPValidityPeriod() {
        Object validityPeriodObject = IdentityUtil.readEventListenerProperty
                (AbstractIdentityHandler.class.getName(), OauthDPoPInterceptorHandlerProxy.class.getName())
                .getProperties().get(DPoPConstants.VALIDITY_PERIOD);

        if (validityPeriodObject == null) {
            return DPoPConstants.DEFAULT_HEADER_VALIDITY;
        }

        String validityPeriodValue = validityPeriodObject.toString();

        if (StringUtils.isNotBlank(validityPeriodValue)) {
            if (StringUtils.isNumeric(validityPeriodValue)) {
                return Integer.parseInt(validityPeriodValue.trim()) * 1000;
            }
            LOG.info("Configured dpop validity period is set to an invalid value. Hence the default validity " +
                    "period will be used.");
            return DPoPConstants.DEFAULT_HEADER_VALIDITY;
        }
        return DPoPConstants.DEFAULT_HEADER_VALIDITY;
    }

    private void setCnFValue(OAuthTokenReqMessageContext tokReqMsgCtx, String tokenBindingValue) {

        JSONObject obj = new JSONObject();
        obj.put(DPoPConstants.JWK_THUMBPRINT, tokenBindingValue);
        tokReqMsgCtx.addProperty(DPoPConstants.CNF, obj);
    }

    private boolean checkAth(String token, JWTClaimsSet jwtClaimsSet) throws IdentityOAuth2ClientException {

        Object ath = jwtClaimsSet.getClaim(DPoPConstants.DPOP_ACCESS_TOKEN_HASH);
        if (ath == null) {
            LOG.error("DPoP Proof access token hash is empty.");
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Error while getting the SHA-256 algorithm.", e);
        }
        byte[] hashBytes = digest.digest(token.getBytes(StandardCharsets.US_ASCII));
        // Encode the hash using base64url encoding
        String hashFromToken = Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes);
        if (!StringUtils.equals(ath.toString(), hashFromToken)) {
            LOG.error("DPoP Proof access token hash mismatch.");
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
        return true;
    }

    private void validateDPoPJKT(OAuth2AccessTokenReqDTO tokenReqDTO, String thumbprint)
            throws IdentityOAuth2Exception {

        if (StringUtils.equals(tokenReqDTO.getGrantType(), DPoPConstants.AUTHORIZATION_CODE_GRANT_TYPE)) {
            String dpopJKT = getPersistedDPoPJKT(tokenReqDTO.getClientId(), tokenReqDTO.getAuthorizationCode());
            if (dpopJKT != null) {
                if (!StringUtils.equals(dpopJKT, thumbprint)) {
                    throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                            DPoPConstants.INVALID_DPOP_ERROR + " : dpop_jkt does not match the thumbprint.");
                }
            }
        }
    }

    private String getPersistedDPoPJKT(String clientId, String authzCode)
            throws IdentityOAuth2Exception {

        if (DPoPJKTCache.getInstance().isEnabled()) {
            DPoPJKTCacheKey cacheKey = new DPoPJKTCacheKey(clientId, authzCode);
            DPoPJKTCacheEntry cacheEntry = DPoPJKTCache.getInstance().getValueFromCache(cacheKey);
            if (cacheEntry != null) {
                String dpopJKT = cacheEntry.getDpopJkt();
                DPoPJKTCache.getInstance().clearCacheEntry(cacheKey);
                //ensures the function returns null only when there is no entry in cache for the given authzCode
                return (dpopJKT == null) ? "" : dpopJKT;
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("dpop_jkt info was not available in cache for client id : " + clientId);
                }
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Retrieving authorization code information from db for client id : " + clientId);
        }
        DPoPJKTDAOImpl dpopJKTDAO = new DPoPJKTDAOImpl();
        return dpopJKTDAO.getDPoPJKTFromAuthzCode(authzCode);
    }

    private boolean isJTIReplay(String jti, int tenantId) throws IdentityOAuth2Exception {

        DPoPJTICache jtiCache = DPoPJTICache.getInstance();
        DPoPJTICacheKey cacheKey = Utils.isTenantIdColumnAvailableInIdnOidcAuth() ?
                new DPoPJTICacheKey(jti, tenantId) : new DPoPJTICacheKey(jti);
        DPoPJTICacheEntry cacheEntry = jtiCache.getValueFromCache(cacheKey);

        if (cacheEntry != null) {

            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                    DPoPConstants.DPOP_PROOF_REPLAYED);
        }

        JWTEntry jwtEntry = getJTIfromDB(jti, tenantId);
        if (jwtEntry == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWT id: " + jti + " not found in the Storage. The JWT has been validated successfully.");
            }
            jtiCache.addToCache(cacheKey, new DPoPJTICacheEntry(null));
            return true;
        } else {
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                    DPoPConstants.DPOP_PROOF_REPLAYED);
        }
    }

    private JWTEntry getJTIfromDB(String jti, final int tenantId) throws IdentityOAuth2Exception {

        List<JWTEntry> jwtEntries = jwtStorageManager.getJwtsFromDB(jti, tenantId);

        if (jwtEntries.isEmpty()) {
            return null;
        }
        // If there is only one entry return it.
        if (jwtEntries.size() == 1) {
            return jwtEntries.get(0);
        }
        return jwtEntries.stream().filter(e -> e.getTenantId() == tenantId).findFirst().orElse(null);
    }

    private void persistJWTID(String jti, long expTime, long timeCreated, int tenantId)
            throws IdentityOAuth2Exception {
        jwtStorageManager.persistJWTIdInDB(jti, tenantId, expTime, timeCreated);
    }
}
