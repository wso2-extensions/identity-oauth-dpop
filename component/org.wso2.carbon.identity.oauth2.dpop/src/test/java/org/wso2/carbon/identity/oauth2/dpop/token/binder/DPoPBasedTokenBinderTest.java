package org.wso2.carbon.identity.oauth2.dpop.token.binder;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfigKey;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.dpop.listener.OauthDPoPInterceptorHandlerProxy;
import org.wso2.carbon.identity.oauth2.dpop.util.Utils;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Properties;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.anyString;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

public class DPoPBasedTokenBinderTest {

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private HttpServletResponse mockResponse;

    @Mock
    private TokenBinding mockTokenBinding;

    private DPoPBasedTokenBinder dPoPBasedTokenBinder;

    private IdentityEventListenerConfig identityEventListenerConfig;

    @BeforeMethod
    public void setUp() {
        dPoPBasedTokenBinder = new DPoPBasedTokenBinder();
        mockRequest = mock(HttpServletRequest.class);
        mockResponse = mock(HttpServletResponse.class);
        mockTokenBinding = mock(TokenBinding.class);

        DPoPBasedTokenBinder.supportedGrantTypesSet = Collections.emptySet();
        
        Properties properties = new Properties();
        properties.put(DPoPConstants.SKIP_DPOP_VALIDATION_IN_REVOKE, "true");

        identityEventListenerConfig = new IdentityEventListenerConfig(
                "true", 1, new IdentityEventListenerConfigKey(), properties);
    }

    @Test
    public void testGetDisplayName() {
        assertEquals(dPoPBasedTokenBinder.getDisplayName(), "DPoP Based");
    }

    @Test
    public void testGetDescription() {
        assertEquals(dPoPBasedTokenBinder.getDescription(), "Bind tokens as DPoP tokens.");
    }

    @Test
    public void testGetBindingType() {
        assertEquals(dPoPBasedTokenBinder.getBindingType(), "DPoP");
    }

    @Test
    public void testGetSupportedGrantTypes() {
        try (MockedStatic<OAuthServerConfiguration> mockedOAuthConfig = mockStatic(OAuthServerConfiguration.class)) {
            OAuthServerConfiguration mockOAuthConfig = mock(OAuthServerConfiguration.class);
            mockedOAuthConfig.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthConfig);
            when(mockOAuthConfig.getSupportedGrantTypes()).thenReturn(Collections.singletonMap("authorization_code", null));

            List<String> supportedGrantTypes = dPoPBasedTokenBinder.getSupportedGrantTypes();
            assertTrue(supportedGrantTypes.contains("authorization_code"));
        }
    }

    @Test
    public void testGetOrGenerateTokenBindingValue() {
        assertNull(dPoPBasedTokenBinder.getOrGenerateTokenBindingValue(mockRequest));
    }

    @Test
    public void testSetTokenBindingValueForResponse() {
        dPoPBasedTokenBinder.setTokenBindingValueForResponse(mockResponse, "dummyBindingValue");
    }

    @Test
    public void testClearTokenBindingElements() {
        dPoPBasedTokenBinder.clearTokenBindingElements(mockRequest, mockResponse);
    }

    @Test
    public void testIsValidTokenBindingWithBindingReference() {
        assertTrue(dPoPBasedTokenBinder.isValidTokenBinding(mockRequest, "dummyBindingReference"));
    }

    @Test
    public void testIsValidTokenBindingWithTokenBinding() throws IdentityOAuth2Exception, ParseException {
        when(mockTokenBinding.getBindingType()).thenReturn(DPoPConstants.OAUTH_DPOP_HEADER);
        when(mockRequest.getRequestURI()).thenReturn(DPoPConstants.OAUTH_REVOKE_ENDPOINT);

        try (MockedStatic<IdentityUtil> mockIdentityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<Utils> mockedUtil = mockStatic(Utils.class)) {

            mockIdentityUtil.when(() -> IdentityUtil.readEventListenerProperty(
                    AbstractIdentityHandler.class.getName(),
                    OauthDPoPInterceptorHandlerProxy.class.getName()))
                    .thenReturn(identityEventListenerConfig);

            mockedUtil.when(() -> Utils.getThumbprintOfKeyFromDpopProof(anyString())).thenReturn("mockThumbprint");
            assertTrue(dPoPBasedTokenBinder.isValidTokenBinding(mockRequest, mockTokenBinding));
        }
    }

    @Test
    public void testGetTokenBindingValueWithHttpServletRequest() throws IdentityOAuth2Exception {
        when(mockRequest.getHeader(DPoPConstants.OAUTH_DPOP_HEADER)).thenReturn("mockDPoPProof");

        try (MockedStatic<Utils> mockedUtil = mockStatic(Utils.class)) {
            mockedUtil.when(() -> Utils.getThumbprintOfKeyFromDpopProof("mockDPoPProof")).thenReturn("mockThumbprint");
            assertEquals(dPoPBasedTokenBinder.getTokenBindingValue(mockRequest), "mockThumbprint");
        }
    }

    @Test
    public void testGetTokenBindingValueWithOAuth2AccessTokenReqDTO() {
        OAuth2AccessTokenReqDTO mockTokenRequest = mock(OAuth2AccessTokenReqDTO.class);
        when(mockTokenRequest.getHttpRequestHeaders()).thenReturn(null);

        assertEquals(dPoPBasedTokenBinder.getTokenBindingValue(mockTokenRequest), Optional.empty());
    }

    @Test
    public void testGetAllGrantTypes() {
        try (MockedStatic<OAuthServerConfiguration> mockedOAuthConfig = mockStatic(OAuthServerConfiguration.class)) {
            OAuthServerConfiguration mockOAuthConfig = mock(OAuthServerConfiguration.class);
            mockedOAuthConfig.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthConfig);
            when(mockOAuthConfig.getSupportedGrantTypes()).thenReturn(Collections.singletonMap("password", null));

            String[] grantTypes = dPoPBasedTokenBinder.getAllGrantTypes();
            assertTrue(Arrays.asList(grantTypes).contains("password"));
        }
    }
}
