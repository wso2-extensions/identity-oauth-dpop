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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.dpop.listener.OauthDPoPInterceptorHandlerProxy;
import org.wso2.carbon.identity.oauth2.dpop.util.Utils;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

/**
 * Test class for DPoPTokenValidator.
 */
public class DPoPTokenValidatorTest {

    private static final String SAMPLE_ENCODED_CERT =
            "MIIFnDCCA4SgAwIBAgIEdBUfHzANBgkqhkiG9w0BAQwFADBoMQswCQYDVQQGEwJM\n" +
                    "SzEQMA4GA1UECBMHV2VzdGVybjEQMA4GA1UEBxMHQ29sb21ibzENMAsGA1UEChME\n" +
                    "V1NPMjEMMAoGA1UECxMDSUFNMRgwFgYDVQQDEw9JbnRlcm1lZGlhdGUgQ0EwHhcN\n" +
                    "MjUwNDA0MTE0NjQ5WhcNMjcwNDA0MTE0NjQ5WjBjMQswCQYDVQQGEwJMSzEQMA4G\n" +
                    "A1UECBMHV2VzdGVybjEQMA4GA1UEBxMHQ29sb21ibzENMAsGA1UEChMEV1NPMjEM\n" +
                    "MAoGA1UECxMDSUFNMRMwEQYDVQQDEwpNeU9yZyBDZXJ0MIICIjANBgkqhkiG9w0B\n" +
                    "AQEFAAOCAg8AMIICCgKCAgEAgZ8BNQXXWkgbzHGQnJxdTt45GnYpmFerirG0GJlO\n" +
                    "bs1EOlb5EOz3xoyIs+/C+upJY+5qWrtzi6inAJiXVhfFzYioJ5ktw/FWWEzmfcfw\n" +
                    "KS63fnUTPDrJbchtzDPDnAYIhcZHOlVNN/CBKhkq3Er2gaJFMcQmEu/S2RCj5Z2w\n" +
                    "CL+OKNW1FIhyUNrf7ixIovxEYqWMkjyF/4xpHFlDEMUNoWKqhuejtiyUwPfzmymw\n" +
                    "fJsi29l1OMWfQO+nw87oBzVWZuMRATYYH1buUolFv40cIIE8A3J1LYK3bO5B3cFT\n" +
                    "eK0n0NO6nxqvdHYloVh4l2Uva9wxh2v7RsVLV4fcPACWcY6cF7uNh4LOWUPbjcc7\n" +
                    "xKskMerjB6P1anMRvnNBeEUsrPOuwRCjUBw3GLzZ1IfCpzBunNz89UFZzSpdiQL7\n" +
                    "fjrz2qULqM4WmVCn0AkSiVe6smeKdm4CcASgaOQaZbuK+mbtT6QK/A6TlgkArRlB\n" +
                    "3ATGsTa4PVkIh1KEWpFS2oodPMKYd4htmcpG3omrpNf/I8/0hqlAkJa+KGEm1ysw\n" +
                    "YaS3tWQCqoEYe3qlDp+n9oCM4FFOL6x5mMULP0YSFYzE+wN65A8H6s52OS8KYfRq\n" +
                    "xBOzcvd2a3Qlig3W/y2gMmMPng+F+zNX4UyxtXJX7o/Y7NlKhU7Y7Y8UHoAMDIW2\n" +
                    "rAcCAwEAAaNTMFEwHQYDVR0OBBYEFEj0pTQ4MKgYJE2lAf2VIG6CU363MA8GA1Ud\n" +
                    "EwQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUw+Fp6ES+VVn2zB9OknrySzGONxswDQYJ\n" +
                    "KoZIhvcNAQEMBQADggIBAERhvsJwFDo2dUGqwpyYI9tl0Hic5i7kl19eUf0uJRHY\n" +
                    "vb2syusa/LEq7Ne2MEvPUYe7fNEC14vqFVKjqPiR2/k0VW/kWQgrLMM8uhsVDdpm\n" +
                    "iPaC1Xif/no5EjGSJes2N1Wg8nCRl/SzotyzOIor819kcCI6O3vAMehD70YZbCZ2\n" +
                    "ma50EvqJUddOxWwaGzE7yNFTCrxyjniLTochWTrrupK2lEX1WsmUefvm87+Ceyjg\n" +
                    "ryWxFfgGJ6y/Mrg9Mice+95EIMFRakX2cPgtDRfsecTgvlofQLFU6gmxEv3GhGoP\n" +
                    "xtIuyB5F/Bw1SE4wIvLkY6otx7UvvZRBRExiQ069weuqGKlOHqvT8jckaTRXslu/\n" +
                    "67LsGAiuGrctSSA6mRYmZoLDad/jWCW957FwJ8im1yJEWFY6v3u0Nd6K312530Y0\n" +
                    "FpHFWplrgiFM6XNbCsVJB7cNcJF2wS8hthnxd3xw7ClZsJmWJAu7UI1b/NoojJ7l\n" +
                    "3pDI4B+vQipcfTjJqgPAWvUz903z61lRuAlJFPPD69l+IQ15z1Mfc7rgl0wmZLBU\n" +
                    "HjVlGsFGQX6e10Rx/msN+NWxKJGf7Z6vxS8Qoc4nddUBnndCOvCVvgI9BThNv0cG\n" +
                    "e3hB2nvCQvUJ/wfuj6i1PNfoM81nA2qEQfjY/QWuF4Ex/RYWBfASNU35TBRVc26R";
    private static final String ACCESS_TOKEN_DO = "AccessTokenDO";

    private PrivilegedCarbonContext privilegedCarbonContext;

    private MockedStatic<IdentityKeyStoreResolver> identityKeyStoreResolverMockedStatic;
    private MockedStatic<PrivilegedCarbonContext> privilegedCarbonContextMockedStatic;

    @BeforeClass
    public void setUp() throws Exception {

        System.setProperty(CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        privilegedCarbonContextMockedStatic = mockStatic(PrivilegedCarbonContext.class);
        privilegedCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockedStatic.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                .thenReturn(privilegedCarbonContext);
        mockKeystores();
    }

    @AfterClass
    public void tearDown() {

        identityKeyStoreResolverMockedStatic.close();
        privilegedCarbonContextMockedStatic.close();
    }

    @Test(description = "Test the resolveSignerCertificate method")
    public void testResolveSignerCertificate() throws Exception {

        DPoPTokenValidator dPoPTokenValidator = new DPoPTokenValidator();
        when(privilegedCarbonContext.getTenantDomain()).thenReturn(SUPER_TENANT_DOMAIN_NAME);
        IdentityProvider identityProvider = mock(IdentityProvider.class);
        when(identityProvider.getIdentityProviderName()).thenReturn(
                IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME);
        X509Certificate certificate = dPoPTokenValidator.resolveSignerCertificate(null, identityProvider);
        assertEquals(certificate.getIssuerDN().getName(), "CN=localhost, O=WSO2, L=Mountain View, ST=CA, C=US");
        when(identityProvider.getIdentityProviderName()).thenReturn("test-idp");
        when(identityProvider.getCertificate()).thenReturn(SAMPLE_ENCODED_CERT);
        certificate = dPoPTokenValidator.resolveSignerCertificate(null, identityProvider);
        assertEquals(certificate.getIssuerDN().getName(),
                "CN=Intermediate CA, OU=IAM, O=WSO2, L=Colombo, ST=Western, C=LK");
    }

    private void mockKeystores() throws Exception {

        IdentityKeyStoreResolver identityKeyStoreResolver = mock(IdentityKeyStoreResolver.class);
        KeyStore keyStore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon",
                System.getProperty(CarbonBaseConstants.CARBON_HOME));
        when(identityKeyStoreResolver.getKeyStore(SUPER_TENANT_DOMAIN_NAME,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(keyStore);
        when(identityKeyStoreResolver.getCertificate(SUPER_TENANT_DOMAIN_NAME,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(
                keyStore.getCertificate("wso2carbon"));
        when(identityKeyStoreResolver.getPrivateKey(SUPER_TENANT_DOMAIN_NAME,
                IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH)).thenReturn(
                keyStore.getKey("wso2carbon", "wso2carbon".toCharArray()));

        identityKeyStoreResolverMockedStatic = mockStatic(IdentityKeyStoreResolver.class);
        identityKeyStoreResolverMockedStatic.when(IdentityKeyStoreResolver::getInstance)
                .thenReturn(identityKeyStoreResolver);
    }

    private KeyStore getKeyStoreFromFile(String keystoreName, String password,
                                         String home) throws Exception {

        Path tenantKeystorePath = Paths.get(home, "repository", "resources", "security", keystoreName);
        FileInputStream file = new FileInputStream(tenantKeystorePath.toString());
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(file, password.toCharArray());
        return keystore;
    }

    @DataProvider(name = "validationRequestDataProvider")
    public Object[][] validationRequestDataProvider() {

        TokenBinding tokenBinding1 = mock(TokenBinding.class);
        when(tokenBinding1.getBindingType()).thenReturn(DPoPConstants.OAUTH_DPOP_HEADER);
        when(tokenBinding1.getBindingValue()).thenReturn("sample-thumb-print");

        AccessTokenDO accessTokenDO1 = mock(AccessTokenDO.class);
        when(accessTokenDO1.getTokenBinding()).thenReturn(tokenBinding1);

        OAuth2TokenValidationRequestDTO.TokenValidationContextParam[] contextParams1 = new
                OAuth2TokenValidationRequestDTO.TokenValidationContextParam[3];

        contextParams1[0] = mock(OAuth2TokenValidationRequestDTO.TokenValidationContextParam.class);
        when(contextParams1[0].getKey()).thenReturn(DPoPConstants.OAUTH_DPOP_HEADER);
        when(contextParams1[0].getValue()).thenReturn("sample-dpop-header");

        contextParams1[1] = mock(OAuth2TokenValidationRequestDTO.TokenValidationContextParam.class);
        when(contextParams1[1].getKey()).thenReturn(DPoPConstants.HTTP_METHOD);
        when(contextParams1[1].getValue()).thenReturn("sample-dpop-http-method");

        contextParams1[2] = mock(OAuth2TokenValidationRequestDTO.TokenValidationContextParam.class);
        when(contextParams1[2].getKey()).thenReturn(DPoPConstants.HTTP_URL);
        when(contextParams1[2].getValue()).thenReturn("sample-dpop-http-url");

        OAuth2TokenValidationRequestDTO.OAuth2AccessToken accessToken1 = mock(
                OAuth2TokenValidationRequestDTO.OAuth2AccessToken.class);
        when(accessToken1.getTokenType()).thenReturn("Bearer");
        when(accessToken1.getIdentifier()).thenReturn("sample.access.token");

        OAuth2TokenValidationRequestDTO requestDTO1 = mock(OAuth2TokenValidationRequestDTO.class);
        when(requestDTO1.getContext()).thenReturn(contextParams1);
        when(requestDTO1.getAccessToken()).thenReturn(accessToken1);

        OAuth2TokenValidationMessageContext validationRequest = mock(OAuth2TokenValidationMessageContext.class);
        when(validationRequest.getProperty(ACCESS_TOKEN_DO)).thenReturn(accessTokenDO1);
        when(validationRequest.getRequestDTO()).thenReturn(requestDTO1);


        return new Object[][]{
                {validationRequest}
        };
    }

    @Test(dataProvider = "validationRequestDataProvider", description = "Test the validateAccessToken method")
    public void testValidateAccessToken(OAuth2TokenValidationMessageContext validationReqDTO)
            throws IdentityOAuth2Exception, ParseException, IdentityProviderManagementException, JOSEException {

        DPoPTokenValidator dPoPTokenValidator = new DPoPTokenValidator();
        JWK jwk = mock(JWK.class);
        when(jwk.isPrivate()).thenReturn(false);
        JWSHeader jwsHeader = mock(JWSHeader.class);
        when(jwsHeader.getJWK()).thenReturn(jwk);
        when(jwsHeader.getAlgorithm()).thenReturn(JWSAlgorithm.RS256);
        JOSEObjectType headerType = mock(JOSEObjectType.class);
        when(headerType.toString()).thenReturn(DPoPConstants.DPOP_JWT_TYPE);
        when(jwsHeader.getType()).thenReturn(headerType);
        SignedJWT signedJWT = mock(SignedJWT.class);
        when(signedJWT.getHeader()).thenReturn(jwsHeader);
        JWTClaimsSet jwtClaimsSet = mock(JWTClaimsSet.class);
        when(jwtClaimsSet.getClaim(DPoPConstants.DPOP_ISSUED_AT)).thenReturn(Date.from(Instant.now()));
        Map<String, Object> claims = new HashMap<>();
        claims.put(DPoPConstants.JTI, "testJti");
        claims.put(DPoPConstants.DPOP_HTTP_METHOD, "sample-dpop-http-method");
        when(jwtClaimsSet.getClaims()).thenReturn(claims);
        when(jwtClaimsSet.getClaim(DPoPConstants.DPOP_HTTP_METHOD)).thenReturn("sample-dpop-http-method");
        when(jwtClaimsSet.getClaim(DPoPConstants.DPOP_HTTP_URI)).thenReturn("sample-dpop-http-url");
        when(jwtClaimsSet.getClaim(DPoPConstants.DPOP_ACCESS_TOKEN_HASH))
                .thenReturn("OWd6_FihO4OX3rxKSPLzMo_d1qzbQqYKbavx4HY5-n4");
        HashMap<String, Object> cnfClaim = new HashMap<>();
        cnfClaim.put(DPoPConstants.JWK_THUMBPRINT, "sample-thumb-print");
        when(jwtClaimsSet.getJSONObjectClaim(DPoPConstants.CNF)).thenReturn(cnfClaim);
        when(jwtClaimsSet.getSubject()).thenReturn("sample-subject");
        when(jwtClaimsSet.getJWTID()).thenReturn("testJti");
        when(jwtClaimsSet.getAudience()).thenReturn(new ArrayList<>());
        when(jwtClaimsSet.getExpirationTime()).thenReturn(Date.from(Instant.now().plusSeconds(300)));
        when(jwtClaimsSet.getIssuer()).thenReturn("sample-issuer");

        when(signedJWT.getJWTClaimsSet()).thenReturn(jwtClaimsSet);

        try (MockedStatic<SignedJWT> mockedSignedJWT =  mockStatic(SignedJWT.class);
             MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<Utils> utils = mockStatic(Utils.class);
             MockedStatic<IdentityProviderManager> mockedIdentityProviderManager =
                mockStatic(IdentityProviderManager.class);
             MockedStatic<IdentityApplicationManagementUtil> mockedStaticIdentityApplicationManagementUtil =
                     mockStatic(IdentityApplicationManagementUtil.class);
             MockedStatic<OAuthServerConfiguration> mockedOAuthServerConfiguration =
                    mockStatic(OAuthServerConfiguration.class);
        ) {

            mockedSignedJWT.when(() -> SignedJWT.parse("sample-dpop-header")).thenReturn(signedJWT);

            IdentityEventListenerConfig identityEventListenerConfig = mock(IdentityEventListenerConfig.class);
            when(identityEventListenerConfig.getProperties()).thenReturn(new Properties());
            mockedIdentityUtil.when(() -> IdentityUtil.readEventListenerProperty(
                    AbstractIdentityHandler.class.getName(), OauthDPoPInterceptorHandlerProxy.class.getName()))
                            .thenReturn(identityEventListenerConfig);
            utils.when(() -> Utils.getThumbprintOfKeyFromDpopProof("sample-dpop-header"))
                    .thenReturn("sample-thumb-print");
            mockedSignedJWT.when(() ->SignedJWT.parse("sample.access.token")).thenReturn(signedJWT);
            when(signedJWT.verify(any(RSASSAVerifier.class))).thenReturn(true);

            IdentityProviderManager identityProviderManager = mock(IdentityProviderManager.class);
            IdentityProvider mockedIdp = mock(IdentityProvider.class);
            when(mockedIdp.getFederatedAuthenticatorConfigs()).thenReturn(new FederatedAuthenticatorConfig[1]);
            when(mockedIdp.getCertificate()).thenReturn(SAMPLE_ENCODED_CERT);
            when(identityProviderManager.getResidentIdP("carbon.super")).thenReturn(mockedIdp);
            mockedIdentityProviderManager.when(IdentityProviderManager::getInstance)
                    .thenReturn(identityProviderManager);
            FederatedAuthenticatorConfig mockFedAuthConfig = mock(FederatedAuthenticatorConfig.class);
            when(mockFedAuthConfig.getProperties()).thenReturn(new Property[1]);
            mockedStaticIdentityApplicationManagementUtil.when(
                    () -> IdentityApplicationManagementUtil.getFederatedAuthenticator(any(), anyString()))
                            .thenReturn(mockFedAuthConfig);
            Property property = new Property();
            property.setValue("sample-issuer");
            mockedStaticIdentityApplicationManagementUtil.when(
                    () -> IdentityApplicationManagementUtil.getProperty(any(Property[].class), anyString()))
                    .thenReturn(property);
            X509Certificate mockedCert = mock(X509Certificate.class);
            PublicKey mockPublicKey = mock(RSAPublicKey.class);
            when(mockedCert.getPublicKey()).thenReturn(mockPublicKey);
            mockedStaticIdentityApplicationManagementUtil.when(
                    () -> IdentityApplicationManagementUtil.decodeCertificate(anyString()))
                    .thenReturn(mockedCert);

            OAuthServerConfiguration mockedOAuthServerConfig = mock(OAuthServerConfiguration.class);
            when(mockedOAuthServerConfig.getTimeStampSkewInSeconds()).thenReturn(1L);
            mockedOAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockedOAuthServerConfig);

            dPoPTokenValidator.validateAccessToken(validationReqDTO);
        }
    }
}
