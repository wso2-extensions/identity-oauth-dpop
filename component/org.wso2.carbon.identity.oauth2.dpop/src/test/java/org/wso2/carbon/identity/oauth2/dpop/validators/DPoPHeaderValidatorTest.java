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

package org.wso2.carbon.identity.oauth2.dpop.validators;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.dpop.util.DPoPProofUtil;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.text.ParseException;
import java.util.Date;
import java.util.Properties;
import java.util.UUID;

import javax.servlet.http.HttpServletRequestWrapper;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants.DEFAULT_HEADER_VALIDITY;
import static org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants.DPOP_JWT_TYPE;
import static org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants.EXPIRED_DPOP_PROOF;
import static org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants.INVALID_DPOP_ERROR;
import static org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants.INVALID_DPOP_PROOF;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.ACCESS_TOKEN;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.ACCESS_TOKEN_HASH;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.DUMMY_CLIENT_ID;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.DUMMY_DPOP_PROOF;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.DUMMY_HTTP_METHOD;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.DUMMY_HTTP_URL;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.DUMMY_JTI;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.DUMMY_TOKEN_BINDING_TYPE;

public class DPoPHeaderValidatorTest {

    @Mock
    private OAuthTokenReqMessageContext tokReqMsgCtx;

    @Mock
    private OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO;

    @Mock
    private HttpServletRequestWrapper httpServletRequest;

    @Mock
    private Properties properties;

    @Mock
    private OAuthAppDO mockOAuthAppDO;

    @Mock
    private OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    private IdentityEventListenerConfig identityEventListenerConfig;

    @Mock
    private SignedJWT mockSignedJWT;

    @Mock
    private JWSHeader mockJWSHeader;

    @Mock
    private JWK mockJWK;

    MockedStatic<IdentityUtil> mockIdentityUtil;

    private DPoPHeaderValidator dPoPHeaderValidator;

    private AutoCloseable closeable;

    @BeforeMethod
    public void setUp() {

        closeable = MockitoAnnotations.openMocks(this);
        mockIdentityUtil = mockStatic(IdentityUtil.class);
        dPoPHeaderValidator = new DPoPHeaderValidator();
        mockIdentityUtil.when(() -> IdentityUtil.readEventListenerProperty(anyString(), anyString()))
                .thenReturn(identityEventListenerConfig);
        when(identityEventListenerConfig.getProperties()).thenReturn(properties);
    }

    @AfterMethod
    public void tearDown() throws Exception {
        mockIdentityUtil.close();
        closeable.close();
    }

    @DataProvider(name = "dpopHeaderProvider")
    public Object[][] getHttpRequestHeaders() {

        return new Object[][] {
                {null, ""},
                {new HttpRequestHeader[] {new HttpRequestHeader("DPoP", DUMMY_DPOP_PROOF)}, DUMMY_DPOP_PROOF},
                {new HttpRequestHeader[] {new HttpRequestHeader("DPoP")}, null},
                {new HttpRequestHeader[] {new HttpRequestHeader("DPoP", DUMMY_DPOP_PROOF, DUMMY_DPOP_PROOF)},
                        "Exception occurred while extracting the DPoP proof header: " +
                        "Request contains multiple DPoP headers."},
        };
    }

    @Test(dataProvider = "dpopHeaderProvider")
    public void testGetDPoPHeader(Object httpRequestHeaders, String expectedResult) {

        try {
            when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
            when(oAuth2AccessTokenReqDTO.getHttpRequestHeaders()).thenReturn((HttpRequestHeader[]) httpRequestHeaders);
            String dPoPHeader = dPoPHeaderValidator.getDPoPHeader(tokReqMsgCtx);
            assertEquals(dPoPHeader, expectedResult);
        } catch (IdentityOAuth2ClientException e) {
            assertEquals(e.getErrorCode(), INVALID_DPOP_PROOF);
            assertEquals(e.getMessage(), expectedResult);
        }
    }

    @Test
    public void testGetApplicationBindingType() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(3600L);
        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(mockOAuthAppDO);
        when(mockOAuthAppDO.getTokenBindingType()).thenReturn(DUMMY_TOKEN_BINDING_TYPE);

        String tokenBindingType = dPoPHeaderValidator.getApplicationBindingType(DUMMY_CLIENT_ID);
        assertEquals(tokenBindingType, DUMMY_TOKEN_BINDING_TYPE);
    }

    @DataProvider(name = "dpopProofProvider")
    public Object[][] getDPoPProof() throws Exception {

        return new Object[][] {
            {DPoPProofUtil.genarateDPoPProof("RSA", DUMMY_JTI, DUMMY_HTTP_METHOD, DUMMY_HTTP_URL),
                    StringUtils.EMPTY},
            {DPoPProofUtil.genarateDPoPProof("EC", DUMMY_JTI, DUMMY_HTTP_METHOD, DUMMY_HTTP_URL),
                    StringUtils.EMPTY},
            {DPoPProofUtil.genarateDPoPProof("RSA", null, DUMMY_HTTP_METHOD, DUMMY_HTTP_URL),
                    INVALID_DPOP_ERROR},
            {DPoPProofUtil.genarateDPoPProof("RSA", DUMMY_JTI, null, DUMMY_HTTP_URL),
                    INVALID_DPOP_ERROR},
            {DPoPProofUtil.genarateDPoPProof("RSA", DUMMY_JTI, "SOME_OTHER_METHOD", DUMMY_HTTP_URL),
                    INVALID_DPOP_ERROR},
            {DPoPProofUtil.genarateDPoPProof("RSA", DUMMY_JTI, DUMMY_HTTP_METHOD, null),
                    INVALID_DPOP_ERROR},
            {DPoPProofUtil.genarateDPoPProof("RSA", DUMMY_JTI, DUMMY_HTTP_METHOD, "SOME_OTHER_URL"),
                    INVALID_DPOP_ERROR},
            {DPoPProofUtil.genarateDPoPProof("RSA", DUMMY_JTI, DUMMY_HTTP_METHOD, DUMMY_HTTP_URL, null),
                    INVALID_DPOP_ERROR},
            {DPoPProofUtil.genarateDPoPProof("RSA", DUMMY_JTI, DUMMY_HTTP_METHOD, DUMMY_HTTP_URL, new Date(0)),
                    EXPIRED_DPOP_PROOF},
        };
    }

    @Test(dataProvider = "dpopProofProvider")
    public void testIsValidDPoPProof(String dPoPProof, String errorMessage) {

        try {
            assertTrue(dPoPHeaderValidator.isValidDPoPProof(DUMMY_HTTP_METHOD, DUMMY_HTTP_URL, dPoPProof));
        } catch (IdentityOAuth2Exception e) {
            assertEquals(e.getErrorCode(), INVALID_DPOP_PROOF);
            assertEquals(e.getMessage(), errorMessage);
        } catch (ParseException e) {
            assertEquals(e.getMessage(), errorMessage);
        }
    }

    @DataProvider(name = "jwtParamProvider")
    public Object[][] getJWSHeader() throws Exception {

        JWTClaimsSet jwtClaimSet = SignedJWT.parse(DPoPProofUtil.genarateDPoPProof()).getJWTClaimsSet();
        return new Object[][] {
                {JWSAlgorithm.RS256, new JOSEObjectType(DPOP_JWT_TYPE), mockJWK, true, jwtClaimSet},
                {null, new JOSEObjectType(DPOP_JWT_TYPE), mockJWK, true, jwtClaimSet},
                {JWSAlgorithm.RS256, new JOSEObjectType("SOME_OTHER_JWT_TYPE"), mockJWK, true, jwtClaimSet},
                {JWSAlgorithm.RS256, new JOSEObjectType(DPOP_JWT_TYPE), null, false, jwtClaimSet},
                {JWSAlgorithm.RS256, new JOSEObjectType(DPOP_JWT_TYPE), mockJWK, false, jwtClaimSet},
                {JWSAlgorithm.RS256, new JOSEObjectType(DPOP_JWT_TYPE), mockJWK, true, null},
        };
    }

    @Test(dataProvider = "jwtParamProvider")
    public void testIsValidDPoPProofWithInvalidJWTParams(Object alg, Object type, Object jwk, Object isValidJWK,
                                                         Object jwtClaimSet) throws Exception {

        try (MockedStatic<SignedJWT> mockedStaticSignedJWT = mockStatic(SignedJWT.class)) {
            mockedStaticSignedJWT.when(() -> SignedJWT.parse(anyString())).thenReturn(mockSignedJWT);
            when(mockSignedJWT.getJWTClaimsSet()).thenReturn((JWTClaimsSet) jwtClaimSet);
            when(mockSignedJWT.getHeader()).thenReturn(mockJWSHeader);
            when(mockJWSHeader.getJWK()).thenReturn((JWK) jwk);
            when(mockJWK.isPrivate()).thenReturn(!((boolean) isValidJWK));
            when(mockJWSHeader.getAlgorithm()).thenReturn((JWSAlgorithm) alg);
            when(mockJWSHeader.getType()).thenReturn((JOSEObjectType) type);
            dPoPHeaderValidator.isValidDPoPProof(DUMMY_HTTP_METHOD, DUMMY_HTTP_URL, DPoPProofUtil.genarateDPoPProof());
        } catch (IdentityOAuth2Exception e) {
            assertEquals(e.getErrorCode(), INVALID_DPOP_PROOF);
            assertEquals(e.getMessage(), INVALID_DPOP_ERROR);
        }
    }

    @DataProvider(name = "getValidityPeriodTestData")
    public Object[][] getValidityPeriod() throws Exception {

        return new Object[][] {
                {DPoPProofUtil.genarateDPoPProof("RSA", DUMMY_JTI, DUMMY_HTTP_METHOD, DUMMY_HTTP_URL,
                        new Date(System.currentTimeMillis() - DEFAULT_HEADER_VALIDITY),
                        ACCESS_TOKEN_HASH, DPOP_JWT_TYPE), "NON_NUMERIC_VALUE"},
                {DPoPProofUtil.genarateDPoPProof("RSA", DUMMY_JTI, DUMMY_HTTP_METHOD, DUMMY_HTTP_URL,
                        new Date(System.currentTimeMillis() - DEFAULT_HEADER_VALIDITY),
                        ACCESS_TOKEN_HASH, DPOP_JWT_TYPE), null},
                {DPoPProofUtil.genarateDPoPProof("RSA", DUMMY_JTI, DUMMY_HTTP_METHOD, DUMMY_HTTP_URL,
                        new Date(System.currentTimeMillis() - DEFAULT_HEADER_VALIDITY),
                        ACCESS_TOKEN_HASH, DPOP_JWT_TYPE), ""},
                {DPoPProofUtil.genarateDPoPProof("RSA", DUMMY_JTI, DUMMY_HTTP_METHOD, DUMMY_HTTP_URL,
                        new Date(System.currentTimeMillis() - 90000),
                        ACCESS_TOKEN_HASH, DPOP_JWT_TYPE), 90},
        };
    }

    @Test(dataProvider = "getValidityPeriodTestData")
    public void testGetValidityPeriod(String dpopProof, Object validityPeriod) throws Exception {

        when(properties.get(DPoPConstants.VALIDITY_PERIOD)).thenReturn(validityPeriod);
        try {
            assertTrue(dPoPHeaderValidator.isValidDPoPProof(DUMMY_HTTP_METHOD, DUMMY_HTTP_URL, dpopProof));
        } catch (IdentityOAuth2Exception e) {
            assertEquals(e.getErrorCode(), INVALID_DPOP_PROOF);
            assertEquals(e.getMessage(), EXPIRED_DPOP_PROOF);
        }
    }

    @DataProvider(name = "isValidDPoPProofWithTokenTestData")
    public Object[][] getIsValidDPoPProofWithTokenTestData() throws Exception {

        return new Object[][] {
                {DPoPProofUtil.genarateDPoPProof("RSA", UUID.randomUUID().toString(), DUMMY_HTTP_METHOD, DUMMY_HTTP_URL,
                        new Date(System.currentTimeMillis()), ACCESS_TOKEN_HASH, DPOP_JWT_TYPE), ACCESS_TOKEN},
                {DPoPProofUtil.genarateDPoPProof("RSA", UUID.randomUUID().toString(), DUMMY_HTTP_METHOD, DUMMY_HTTP_URL,
                        new Date(System.currentTimeMillis()), "SOME_OTHER_HASH", DPOP_JWT_TYPE), ACCESS_TOKEN},
                {DPoPProofUtil.genarateDPoPProof("RSA", UUID.randomUUID().toString(), DUMMY_HTTP_METHOD, DUMMY_HTTP_URL,
                        new Date(System.currentTimeMillis()), null, DPOP_JWT_TYPE), ACCESS_TOKEN},
        };
    }

    @Test(dataProvider = "isValidDPoPProofWithTokenTestData")
    public void testIsValidDPoPProofWithToken(String dPoPProof, String token) throws Exception {

        try {
            assertTrue(dPoPHeaderValidator.isValidDPoPProof(DUMMY_HTTP_METHOD, DUMMY_HTTP_URL, dPoPProof, token));
        } catch (IdentityOAuth2Exception e) {
            assertEquals(e.getErrorCode(), INVALID_DPOP_PROOF);
            assertEquals(e.getMessage(), INVALID_DPOP_ERROR);
        }
    }

    @DataProvider(name = "isValidDPoPTestData")
    public Object[][] getIsValidDPoPTestData() throws Exception {

        return new Object[][] {
            {DUMMY_DPOP_PROOF},
            {DPoPProofUtil.genarateDPoPProof()},
        };
    }

    @Test(dataProvider = "isValidDPoPTestData")
    public void testIsValidDPoP(String dPoPProof) {

        when(oAuth2AccessTokenReqDTO.getHttpServletRequestWrapper()).thenReturn(httpServletRequest);
        when(httpServletRequest.getMethod()).thenReturn(DUMMY_HTTP_METHOD);
        when(httpServletRequest.getRequestURI()).thenReturn(DUMMY_HTTP_URL);
        when(OAuth2Util.buildServiceUrl(DUMMY_HTTP_URL, null, null))
                .thenReturn(DUMMY_HTTP_URL);
        try {
            assertTrue(dPoPHeaderValidator.isValidDPoP(dPoPProof, oAuth2AccessTokenReqDTO, tokReqMsgCtx));
        } catch (IdentityOAuth2Exception e) {
            assertEquals(e.getErrorCode(), INVALID_DPOP_PROOF);
            assertEquals(e.getMessage(), INVALID_DPOP_ERROR);
        }
    }
}
