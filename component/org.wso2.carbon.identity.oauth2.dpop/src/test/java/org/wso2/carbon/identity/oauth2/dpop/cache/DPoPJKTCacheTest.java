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

package org.wso2.carbon.identity.oauth2.dpop.cache;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.utils.CarbonUtils;

import static org.mockito.Mockito.mockStatic;

public class DPoPJKTCacheTest {

    private DPoPJKTCache dPoPJKTCache;
    private static MockedStatic<IdentityTenantUtil> tenantUtilMock;

    @BeforeClass
    public void setUpMock() {
        tenantUtilMock = mockStatic(IdentityTenantUtil.class, Mockito.CALLS_REAL_METHODS);
        tenantUtilMock.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
    }

    @AfterClass
    public void tearDownMock() {
        if (tenantUtilMock != null) {
            tenantUtilMock.close();
        }
    }

    @BeforeMethod
    public void setUp() {
        try (MockedStatic<CarbonUtils> carbonUtilsMock = mockStatic(CarbonUtils.class, Mockito.CALLS_REAL_METHODS)) {

            carbonUtilsMock.when(CarbonUtils::getCarbonHome).thenReturn(System.getProperty(CarbonBaseConstants.CARBON_HOME));

            dPoPJKTCache = DPoPJKTCache.getInstance();
        }
    }

    @Test
    public void testGetSingletonInstance() {
        DPoPJKTCache instance = DPoPJKTCache.getInstance();
        Assert.assertNotNull(dPoPJKTCache);
        Assert.assertNotNull(instance);
        Assert.assertEquals(instance, dPoPJKTCache);
    }

    @Test
    public void testCachePutAndGet() {
        DPoPJKTCacheKey cacheKey = new DPoPJKTCacheKey("test-jkt", "test-code");
        DPoPJKTCacheEntry cacheEntry = new DPoPJKTCacheEntry("test-value");

        dPoPJKTCache.addToCache(cacheKey, cacheEntry);
        DPoPJKTCacheEntry retrievedEntry = dPoPJKTCache.getValueFromCache(cacheKey);

        Assert.assertNotNull(retrievedEntry, "Cache retrieval failed!");
        Assert.assertEquals(retrievedEntry.getDpopJkt(), "test-value", "Cache value mismatch!");
    }
    @Test
    public void testCacheRemove() {
        DPoPJKTCacheKey cacheKey = new DPoPJKTCacheKey("test-jkt", "test-code");
        DPoPJKTCacheEntry cacheEntry = new DPoPJKTCacheEntry("test-value");

        dPoPJKTCache.addToCache(cacheKey, cacheEntry);

        Assert.assertNotNull(dPoPJKTCache.getValueFromCache(cacheKey), "Cache entry was not stored properly!");

        dPoPJKTCache.clearCacheEntry(cacheKey);

        Assert.assertNull(dPoPJKTCache.getValueFromCache(cacheKey), "Cache entry was not removed!");
    }
}
