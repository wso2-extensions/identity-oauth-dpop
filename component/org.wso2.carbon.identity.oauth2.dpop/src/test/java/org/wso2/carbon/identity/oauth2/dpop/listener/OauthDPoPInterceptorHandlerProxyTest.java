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

import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.dpop.dao.DPoPTokenManagerDAO;
import org.wso2.carbon.identity.oauth2.dpop.internal.DPoPDataHolder;
import org.wso2.carbon.identity.oauth2.dpop.util.Utils;
import org.wso2.carbon.identity.oauth2.dpop.validators.DPoPHeaderValidator;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import javax.servlet.http.HttpServletRequestWrapper;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.DUMMY_APP_RESIDENT_TENANT_DOMAIN;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.DUMMY_HTTP_METHOD;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.DUMMY_HTTP_URL;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.DUMMY_TENANT_DOMAIN;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.DUMMY_TOKEN_BINDING_TYPE;

@WithCarbonHome
public class OauthDPoPInterceptorHandlerProxyTest {

    private static final String DUMMY_REFRESH_TOKEN = "dummyRefreshToken";

    private DPoPHeaderValidator dPoPHeaderValidator;

    private OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO;
    private OAuthTokenReqMessageContext tokReqMsgCtx;

    MockedStatic<OAuth2Util> oAuth2UtilMockedStatic;
    MockedStatic<Utils> utilsMockedStatic;

    @BeforeMethod
    public void setUp() {

        dPoPHeaderValidator = new DPoPHeaderValidator();
        oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokReqMsgCtx = createTokenReqMessageContext();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(DUMMY_TENANT_DOMAIN);

        oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class);
        oAuth2UtilMockedStatic.when(OAuth2Util::getAppResidentTenantDomain).
                thenReturn(DUMMY_APP_RESIDENT_TENANT_DOMAIN);

        utilsMockedStatic = mockStatic(Utils.class);
        utilsMockedStatic.when(() -> Utils.getApplicationBindingType(anyString(), anyString())).
                thenReturn(DUMMY_TOKEN_BINDING_TYPE);
    }

    @AfterMethod
    public void tearDown() {

        oAuth2UtilMockedStatic.close();
        utilsMockedStatic.close();
    }

    @Test
    public void testOnPreAccessToken() throws Exception {

        OauthDPoPInterceptorHandlerProxy oauthDPoPInterceptorHandlerProxy =
                new OauthDPoPInterceptorHandlerProxy(dPoPHeaderValidator);

        oauthDPoPInterceptorHandlerProxy.onPreTokenIssue(oAuth2AccessTokenReqDTO, tokReqMsgCtx, null);
    }

    @Test
    public void testOnPreTokenRenewalSkipsBindingLookupForNonDPoPApplication() throws Exception {

        utilsMockedStatic.when(() -> Utils.getResolvedApplicationBindingType(any())).thenReturn("sso-session");
        DPoPTokenManagerDAO tokenManagerDAO = mock(DPoPTokenManagerDAO.class);
        OauthDPoPInterceptorHandlerProxy oauthDPoPInterceptorHandlerProxy = createProxyWithDao(tokenManagerDAO);
        oAuth2AccessTokenReqDTO.setRefreshToken(DUMMY_REFRESH_TOKEN);

        oauthDPoPInterceptorHandlerProxy.onPreTokenRenewal(oAuth2AccessTokenReqDTO, tokReqMsgCtx, null);

        verify(tokenManagerDAO, never()).getTokenBindingUsingHash(anyString());
    }

    @Test
    public void testOnPreTokenRenewalForDPoPApplicationWithUnboundRefreshToken() throws Exception {

        utilsMockedStatic.when(() -> Utils.getResolvedApplicationBindingType(any()))
                .thenReturn(DPoPConstants.DPOP_TOKEN_TYPE);
        DPoPTokenManagerDAO tokenManagerDAO = mock(DPoPTokenManagerDAO.class);
        OauthDPoPInterceptorHandlerProxy oauthDPoPInterceptorHandlerProxy = createProxyWithDao(tokenManagerDAO);
        oAuth2AccessTokenReqDTO.setRefreshToken(DUMMY_REFRESH_TOKEN);

        oauthDPoPInterceptorHandlerProxy.onPreTokenRenewal(oAuth2AccessTokenReqDTO, tokReqMsgCtx, null);

        verify(tokenManagerDAO, times(1)).getTokenBindingUsingHash(DUMMY_REFRESH_TOKEN);
    }

    private OauthDPoPInterceptorHandlerProxy createProxyWithDao(DPoPTokenManagerDAO tokenManagerDAO) {

        DPoPDataHolder dataHolder = DPoPDataHolder.getInstance();
        DPoPTokenManagerDAO previousDAO = dataHolder.getTokenBindingTypeManagerDao();
        dataHolder.setTokenBindingTypeManagerDao(tokenManagerDAO);
        try {
            return new OauthDPoPInterceptorHandlerProxy(dPoPHeaderValidator);
        } finally {
            dataHolder.setTokenBindingTypeManagerDao(previousDAO);
        }
    }

    private OAuthTokenReqMessageContext createTokenReqMessageContext() {

        OAuthTokenReqMessageContext tokenReqMessageContext =
                new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);

        HttpServletRequestWrapper httpServletRequestWrapper = mock(HttpServletRequestWrapper.class);
        when(httpServletRequestWrapper.getMethod()).thenReturn(DUMMY_HTTP_METHOD);
        when(httpServletRequestWrapper.getRequestURI()).thenReturn(DUMMY_HTTP_URL);
        oAuth2AccessTokenReqDTO.setHttpServletRequestWrapper(httpServletRequestWrapper);

        return tokenReqMessageContext;
    }
}
