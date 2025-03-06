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

package org.wso2.carbon.identity.oauth2.dpop.listener;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.dpop.validators.DPoPHeaderValidator;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;

import java.util.Collections;
import java.util.Map;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class OauthDPoPInterceptorHandlerProxyTest {
    @Mock
    private DPoPHeaderValidator mockDPoPHeaderValidator;

    @Mock
    private OAuth2AccessTokenReqDTO mockTokenReqDTO;

    @Mock
    private OAuthTokenReqMessageContext mockTokReqMsgCtx;

    @Mock
    private OAuth2AccessTokenRespDTO mockTokenRespDTO;

    @Mock
    private TokenBinding mockTokenBinding;

    private OauthDPoPInterceptorHandlerProxy dPoPInterceptorHandler;

    @BeforeClass
    public void setUpMocks() {
        MockitoAnnotations.openMocks(this);
        dPoPInterceptorHandler = new OauthDPoPInterceptorHandlerProxy(mockDPoPHeaderValidator);
    }

    @BeforeMethod
    public void setUp() {
        Mockito.reset(mockDPoPHeaderValidator, mockTokenRespDTO, mockTokReqMsgCtx, mockTokenBinding);
    }

    @DataProvider(name = "emptyParamsProvider")
    public Object[][] provideEmptyParams() {
        return new Object[][] {
                { Collections.emptyMap() }
        };
    }

    @Test(dataProvider = "emptyParamsProvider")
    public void testOnPreTokenIssueWithValidDPoPProof(Map<String, Object> params) throws Exception {
        when(mockTokenReqDTO.getClientId()).thenReturn("test-client");
        when(mockDPoPHeaderValidator.getApplicationBindingType(anyString())).thenReturn(DPoPConstants.DPOP_TOKEN_TYPE);
        when(mockDPoPHeaderValidator.getDPoPHeader(mockTokReqMsgCtx)).thenReturn("valid-proof");
        when(mockDPoPHeaderValidator.isValidDPoP(anyString(), any(), any())).thenReturn(true);

        dPoPInterceptorHandler.onPreTokenIssue(mockTokenReqDTO, mockTokReqMsgCtx, params);

        verify(mockDPoPHeaderValidator, times(1)).isValidDPoP(anyString(), any(), any());
    }


    @Test(dataProvider = "emptyParamsProvider", expectedExceptions = IdentityOAuth2ClientException.class)
    public void testOnPreTokenIssueWithMissingDPoPProof(Map<String, Object> params) throws Exception {
        when(mockTokenReqDTO.getClientId()).thenReturn("test-client");
        when(mockDPoPHeaderValidator.getApplicationBindingType(anyString())).thenReturn(DPoPConstants.DPOP_TOKEN_TYPE);
        when(mockDPoPHeaderValidator.getDPoPHeader(mockTokReqMsgCtx)).thenReturn(null);

        dPoPInterceptorHandler.onPreTokenIssue(mockTokenReqDTO, mockTokReqMsgCtx, params);
    }

    @Test(dataProvider = "emptyParamsProvider", expectedExceptions = IdentityOAuth2ClientException.class)
    public void testOnPreTokenIssueWithInvalidDPoPProof(Map<String, Object> params) throws Exception {
        when(mockTokenReqDTO.getClientId()).thenReturn("test-client");
        when(mockDPoPHeaderValidator.getApplicationBindingType(anyString())).thenReturn(DPoPConstants.DPOP_TOKEN_TYPE);
        when(mockDPoPHeaderValidator.getDPoPHeader(mockTokReqMsgCtx)).thenReturn("invalid-proof");
        when(mockDPoPHeaderValidator.isValidDPoP(anyString(), any(), any())).thenReturn(false);

        dPoPInterceptorHandler.onPreTokenIssue(mockTokenReqDTO, mockTokReqMsgCtx, params);
    }

    @Test(dataProvider = "emptyParamsProvider")
    public void testOnPostTokenIssueWithSetsTokenTypeToDPoP(Map<String, Object> params) {
        when(mockTokReqMsgCtx.getTokenBinding()).thenReturn(mockTokenBinding);
        when(mockTokenBinding.getBindingType()).thenReturn(DPoPConstants.DPOP_TOKEN_TYPE);

        dPoPInterceptorHandler.onPostTokenIssue(mockTokenReqDTO, mockTokenRespDTO, mockTokReqMsgCtx, params);

        verify(mockTokenRespDTO, times(1)).setTokenType(DPoPConstants.DPOP_TOKEN_TYPE);
    }

    @Test
    public void testIsEnabled() {
        try (MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {
            IdentityEventListenerConfig config = mock(IdentityEventListenerConfig.class);
            when(config.getEnable()).thenReturn("true");
            mockedIdentityUtil.when(
                    () -> IdentityUtil.readEventListenerProperty(anyString(), anyString())
            ).thenReturn(config);

            Assert.assertTrue(dPoPInterceptorHandler.isEnabled());
        }
    }
}
