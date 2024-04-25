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

package org.wso2.carbon.identity.oauth2.dpop.cache;

import java.io.Serializable;

/**
 * Cache key for DPoP JKT.
 */
public class DPoPJKTCacheKey implements Serializable {

    private String cacheKeyString;

    public DPoPJKTCacheKey(String clientId, String authzCode) {

        this.cacheKeyString = clientId + ":" + authzCode;
    }

    private static final long serialVersionUID = 5023478840178742769L;
    public String getCacheKeyString() {

        return cacheKeyString;
    }

    @Override
    public boolean equals(Object o) {

        if (!(o instanceof DPoPJKTCacheKey)) {
            return false;
        }
        return this.cacheKeyString.equals(((DPoPJKTCacheKey) o).getCacheKeyString());
    }

    @Override
    public int hashCode() {

        return cacheKeyString.hashCode();
    }
}
