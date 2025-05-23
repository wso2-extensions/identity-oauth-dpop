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

package org.wso2.carbon.identity.oauth2.dpop.introspection.dataprovider;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenProvider;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.dpop.internal.DPoPDataHolder;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

public class DPoPIntrospectionDataProviderTest {

    @Mock
    private OAuth2IntrospectionResponseDTO introspectionResponseDTO;
    
    @Mock
    private AccessTokenDO accessTokenDO;
    
    @Mock
    private TokenBinding tokenBinding;

    @Mock
    private TokenProvider tokenProvider;

    @Mock
    private OAuthServerConfiguration mockedOAuthServerConfiguration;

    @Mock
    private OAuth2TokenValidationRequestDTO tokenValidationRequestDTO;

    @Mock
    private OAuth2TokenValidationRequestDTO.OAuth2AccessToken accessToken;
    
    private DPoPIntrospectionDataProvider introspectionDataProvider;

    @BeforeClass
    public void setUpClass() {

        tokenProvider = mock(TokenProvider.class);
        tokenBinding = mock(TokenBinding.class);
        accessTokenDO = mock(AccessTokenDO.class);
        tokenValidationRequestDTO = new OAuth2TokenValidationRequestDTO();
        accessToken = tokenValidationRequestDTO.new OAuth2AccessToken();
        accessToken.setIdentifier("accessTokenId");
        tokenValidationRequestDTO.setAccessToken(accessToken);
        this.introspectionResponseDTO = new OAuth2IntrospectionResponseDTO();
    }

    @BeforeMethod
    public void setUp() {

        introspectionDataProvider = new DPoPIntrospectionDataProvider();
    }

    @Test
    public void testGetIntrospectionDataForRefreshToken() throws IdentityOAuth2Exception {

        when(tokenBinding.getBindingType()).thenReturn(DPoPConstants.DPOP_TOKEN_TYPE);
        when(tokenBinding.getBindingValue()).thenReturn("jwk-thumbprint");
        accessTokenDO.setTokenBinding(tokenBinding);

        when(accessTokenDO.getTokenBinding()).thenReturn(tokenBinding);
        when(tokenProvider.getVerifiedRefreshToken("accessTokenId")).thenReturn(accessTokenDO);
        DPoPDataHolder.getInstance().setTokenProvider(tokenProvider);

        this.introspectionResponseDTO.setTokenType("Refresh");

        Map<String, Object> result = introspectionDataProvider.getIntrospectionData(
                tokenValidationRequestDTO, introspectionResponseDTO);

        Assert.assertEquals(result.get(DPoPConstants.TOKEN_TYPE), DPoPConstants.DPOP_TOKEN_TYPE);
        Assert.assertNotNull(result.get(DPoPConstants.CNF));
    }

    @Test
    public void testGetIntrospectionDataForAccessToken() throws IdentityOAuth2Exception {

        when(tokenBinding.getBindingType()).thenReturn(DPoPConstants.DPOP_TOKEN_TYPE);
        when(tokenBinding.getBindingValue()).thenReturn("jwk-thumbprint");
        accessTokenDO.setTokenBinding(tokenBinding);

        when(accessTokenDO.getTokenBinding()).thenReturn(tokenBinding);

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                        OAuthServerConfiguration.class);
                MockedStatic<OAuth2Util> oAuth2Util = mockStatic(OAuth2Util.class)) {

            mockedOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(
                    OAuthServerConfiguration::getInstance).thenReturn(mockedOAuthServerConfiguration);
            when(mockedOAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(360L);

            oAuth2Util.when(() -> OAuth2Util.findAccessToken(any(), anyBoolean())).thenReturn(accessTokenDO);

            this.introspectionResponseDTO.setTokenType("Bearer");

            Map<String, Object> result = introspectionDataProvider.getIntrospectionData(
                    tokenValidationRequestDTO, introspectionResponseDTO);

            Assert.assertEquals(result.get(DPoPConstants.TOKEN_TYPE), DPoPConstants.DPOP_TOKEN_TYPE);
            Assert.assertNotNull(result.get(DPoPConstants.CNF));
        }
    }
}
