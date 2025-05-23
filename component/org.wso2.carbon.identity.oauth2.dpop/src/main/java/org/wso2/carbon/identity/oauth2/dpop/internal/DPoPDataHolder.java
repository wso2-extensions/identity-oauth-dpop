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

package org.wso2.carbon.identity.oauth2.dpop.internal;

import org.wso2.carbon.identity.oauth.tokenprocessor.DefaultTokenProvider;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenProvider;
import org.wso2.carbon.identity.oauth2.dpop.dao.DPoPTokenManagerDAO;

/**
 * DPoP data holder.
 */
public class DPoPDataHolder {

    private static final DPoPDataHolder dPoPDataHolder = new DPoPDataHolder();
    private DPoPTokenManagerDAO tokenBindingTypeManagerDao;
    private static boolean isDPoPJKTTableEnabled = false;
    private TokenProvider tokenProvider;

    public static DPoPDataHolder getInstance() {

        return dPoPDataHolder;
    }

    public static DPoPDataHolder getDPoPDataHolder() {

        return dPoPDataHolder;
    }

    /**
     * Get Token binding type manager dao.
     *
     * @return TokenBindingTypeManagerDao
     */
    public DPoPTokenManagerDAO getTokenBindingTypeManagerDao() {

        return tokenBindingTypeManagerDao;
    }

    /**
     * Set Token binding type manager dao.
     *
     * @param tokenBindingTypeManagerDao TokenBindingTypeManagerDao
     */
    public void setTokenBindingTypeManagerDao(
            DPoPTokenManagerDAO tokenBindingTypeManagerDao) {

        this.tokenBindingTypeManagerDao = tokenBindingTypeManagerDao;
    }

    public static boolean isDPoPJKTTableEnabled() {

        return isDPoPJKTTableEnabled;
    }

    public static void setDPoPJKTTableEnabled(boolean isDPoPJKTTableEnabled) {

        DPoPDataHolder.isDPoPJKTTableEnabled = isDPoPJKTTableEnabled;
    }

    /**
     * Get token provider.
     *
     * @return TokenProvider
     */
    public TokenProvider getTokenProvider() {

        if (tokenProvider == null) {
            tokenProvider = new DefaultTokenProvider();
        }
        return tokenProvider;
    }

    /**
     * Set token provider.
     *
     * @param tokenProvider TokenProvider
     */
    public void setTokenProvider(TokenProvider tokenProvider) {

        this.tokenProvider = tokenProvider;
    }
}
