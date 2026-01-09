/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.dpop.handler;

import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.dpop.util.Utils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;
import static org.wso2.carbon.identity.oauth.par.common.ParConstants.PRE_HANDLE_PAR_REQUEST;
import static org.wso2.carbon.identity.oauth.par.common.ParConstants.REQUEST_HEADERS;
import static org.wso2.carbon.identity.oauth.par.common.ParConstants.REQUEST_PARAMETERS;

/**
 * Test class for DPoPEventHandler.
 */
@WithCarbonHome
public class DPoPEventHandlerTest {

    private MockedStatic<Utils> utilsMockedStatic;
    private MockedStatic<OAuth2Util> oAuth2UtilMockedStatic;
    private MockedStatic<PrivilegedCarbonContext> privilegedCarbonContextMockedStatic;
    private MockedStatic<SessionDataCache> sessionDataCacheMockedStatic;
    private SessionDataCache sessionDataCache;

    @BeforeMethod
    public void setUp() {

        utilsMockedStatic = mockStatic(Utils.class);
        oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class);
        privilegedCarbonContextMockedStatic = mockStatic(PrivilegedCarbonContext.class);
        sessionDataCacheMockedStatic = mockStatic(SessionDataCache.class);

        PrivilegedCarbonContext privilegedCarbonContext = mock(PrivilegedCarbonContext.class);
        sessionDataCache = mock(SessionDataCache.class);

        privilegedCarbonContextMockedStatic.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                .thenReturn(privilegedCarbonContext);
        when(privilegedCarbonContext.getTenantDomain()).thenReturn("carbon.super");
        oAuth2UtilMockedStatic.when(OAuth2Util::getAppResidentTenantDomain).thenReturn(null);
        sessionDataCacheMockedStatic.when(SessionDataCache::getInstance).thenReturn(sessionDataCache);
    }

    @AfterMethod
    public void tearDown() {

        if (utilsMockedStatic != null) {
            utilsMockedStatic.close();
        }
        if (oAuth2UtilMockedStatic != null) {
            oAuth2UtilMockedStatic.close();
        }
        if (privilegedCarbonContextMockedStatic != null) {
            privilegedCarbonContextMockedStatic.close();
        }
        if (sessionDataCacheMockedStatic != null) {
            sessionDataCacheMockedStatic.close();
        }
    }

    @Test
    public void testHandleEventWhenTokenBindingTypeIsNotDPoP() throws Exception {

        Event event = mock(Event.class);
        when(event.getEventName()).thenReturn(PRE_HANDLE_PAR_REQUEST);

        Map<String, Object> eventProperties = new HashMap<>();
        Map<String, Enumeration<String>> headers = new HashMap<>();
        Map<String, String> parameters = new HashMap<>();

        String clientId = "testClientId";
        parameters.put(DPoPConstants.CLIENT_ID, clientId);

        Enumeration<String> dPoPProofEnum = Collections.enumeration(Collections.singletonList("mockDPoPProof"));
        headers.put(DPoPConstants.OAUTH_DPOP_HEADER.toLowerCase(), dPoPProofEnum);

        eventProperties.put(REQUEST_HEADERS, headers);
        eventProperties.put(REQUEST_PARAMETERS, parameters);
        when(event.getEventProperties()).thenReturn(eventProperties);

        utilsMockedStatic.when(() -> Utils.getApplicationBindingType(eq(clientId), anyString()))
                .thenReturn("TestBindingType");

        DPoPEventHandler dPoPEventHandler = new DPoPEventHandler();
        dPoPEventHandler.handleEvent(event);

        // Verify that dpop_jkt was not added to parameters
        assertFalse(parameters.containsKey(DPoPConstants.DPOP_JKT));
    }

    @Test
    public void testHandleEventWhenEventNameIsNotSupported() throws Exception {

        Event event = mock(Event.class);
        when(event.getEventName()).thenReturn("UNSUPPORTED_EVENT");
        when(event.getEventProperties()).thenReturn(new HashMap<>());

        DPoPEventHandler dPoPEventHandler = new DPoPEventHandler();
        dPoPEventHandler.handleEvent(event);
    }

    @Test
    public void testHandleEventPostIssueCodeWhenTokenBindingTypeIsNotDPoP() throws Exception {

        Event event = mock(Event.class);
        when(event.getEventName()).thenReturn(OIDCConstants.Event.POST_ISSUE_CODE);

        String codeId = "testCodeId";
        String sessionDataKey = "testSessionDataKey";
        String clientId = "testClientId";

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(OIDCConstants.Event.CODE_ID, codeId);
        eventProperties.put(OIDCConstants.Event.SESSION_DATA_KEY, sessionDataKey);
        when(event.getEventProperties()).thenReturn(eventProperties);

        // Mock SessionDataCacheEntry
        SessionDataCacheEntry sessionDataCacheEntry = mock(SessionDataCacheEntry.class);
        Map<String, String[]> paramMap = new HashMap<>();
        paramMap.put(DPoPConstants.CLIENT_ID, new String[]{clientId});
        paramMap.put(DPoPConstants.DPOP_JKT, new String[]{"testDPoPJKT"});
        when(sessionDataCacheEntry.getParamMap()).thenReturn(paramMap);
        when(sessionDataCache.getValueFromCache(any(SessionDataCacheKey.class))).thenReturn(sessionDataCacheEntry);

        // Mock token binding type as "Bearer" instead of "DPoP"
        utilsMockedStatic.when(() -> Utils.getApplicationBindingType(eq(clientId), anyString()))
                .thenReturn("TestBindingType");

        DPoPEventHandler dPoPEventHandler = new DPoPEventHandler();
        dPoPEventHandler.handleEvent(event);

        // Verify that getApplicationBindingType was called
        utilsMockedStatic.verify(() -> Utils.getApplicationBindingType(eq(clientId), anyString()));
    }
}
