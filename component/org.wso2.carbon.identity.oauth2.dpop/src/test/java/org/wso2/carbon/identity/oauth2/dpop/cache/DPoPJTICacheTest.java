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

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithRealmService;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

@WithCarbonHome
@WithRealmService
public class DPoPJTICacheTest {

    private DPoPJTICache dPoPJTICache;
    private DPoPJTICacheEntry jtiCacheEntry;
    private DPoPJTICacheKey jtiCacheKey;

    @BeforeClass
    public void setUp() throws Exception {

        dPoPJTICache = DPoPJTICache.getInstance();

        jtiCacheEntry = new DPoPJTICacheEntry(null);
        jtiCacheKey = new DPoPJTICacheKey("some-key", -1234);
    }

    @Test
    public void testAddToCache() throws Exception {

        dPoPJTICache.addToCache(jtiCacheKey, jtiCacheEntry);

    }

    @Test(dependsOnMethods = {"testAddToCache"})
    public void testGetValueFromCache() throws Exception {

        assertEquals(dPoPJTICache.getValueFromCache(jtiCacheKey), jtiCacheEntry);
    }

    @Test(dependsOnMethods = {"testGetValueFromCache"})
    public void testClearCacheEntry() throws Exception {

        dPoPJTICache.clearCacheEntry(jtiCacheKey);
        assertNull(dPoPJTICache.getValueFromCache(jtiCacheKey));

    }
}
