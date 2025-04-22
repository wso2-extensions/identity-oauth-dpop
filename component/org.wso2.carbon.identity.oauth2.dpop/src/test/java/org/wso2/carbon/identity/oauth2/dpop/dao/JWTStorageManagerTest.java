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

package org.wso2.carbon.identity.oauth2.dpop.dao;

import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.dpop.util.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

@WithH2Database(files = {"dbScripts/h2.sql"})
@WithCarbonHome
public class JWTStorageManagerTest {

    private JWTStorageManager jwtStorageManager;

    private MockedStatic<Utils> mockUtils;

    @BeforeClass
    public void setUp() {

        jwtStorageManager = new JWTStorageManager();
    }

    @BeforeMethod
    public void init() {

        mockUtils = mockStatic(Utils.class);
    }

    @AfterMethod
    public void tearDown() {

        if (mockUtils != null) {
            mockUtils.close();
        }
    }

    @Test(priority = 1)
    public void testGetJwtsFromDBWithNoEntry() throws Exception {

        mockUtils.when(Utils::isTenantIdColumnAvailableInIdnOidcAuth)
                .thenReturn(false);

        mockUtils.when(() -> Utils.getDBQuery(DPoPConstants.GET_JWT))
                .thenReturn(DPoPConstants.SQLQueries.GET_JWT);

        List<JWTEntry> results = jwtStorageManager.getJwtsFromDB("jti", 1);
        assertTrue(results.isEmpty(), "Expected empty result set");
    }

    @Test(priority = 2)
    public void persistJTIinDB() throws Exception {

        mockUtils.when(Utils::isTenantIdColumnAvailableInIdnOidcAuth)
                .thenReturn(true);

        mockUtils.when(() -> Utils.getDBQuery(DPoPConstants.INSERT_JWD_ID))
                .thenReturn(DPoPConstants.SQLQueries.INSERT_TENANTED_JWD_ID);

        String testJti = "test-jti-123";
        int testTenantId = 1;
        long testExpTime = System.currentTimeMillis() + 3600000; // 1 hour in future
        long testTimeCreated = System.currentTimeMillis();

        jwtStorageManager.persistJWTIdInDB(testJti, testTenantId, testExpTime, testTimeCreated);
    }

    @Test(priority = 3)
    public void testGetJwtsFromDB() throws Exception {

        mockUtils.when(Utils::isTenantIdColumnAvailableInIdnOidcAuth)
                .thenReturn(true);

        mockUtils.when(() -> Utils.getDBQuery(DPoPConstants.GET_JWT_DETAILS))
                .thenReturn(DPoPConstants.SQLQueries.GET_JWT_DETAIL);

        List<JWTEntry> results = jwtStorageManager.getJwtsFromDB("test-jti-123", 1);
        assertEquals(results.size(), 1, "Expected result set size of 1");
    }

    @Test(priority = 4, expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetJwtsFromDBWithSQLException() throws Exception {

        try (MockedStatic<IdentityDatabaseUtil> ignored = mockStaticDBUtils("executeQuery",
                new SQLException("Test Exception"))) {

            mockUtils.when(Utils::isTenantIdColumnAvailableInIdnOidcAuth)
                    .thenReturn(true);
            mockUtils.when(() -> Utils.getDBQuery(DPoPConstants.GET_JWT_DETAILS))
                    .thenReturn(DPoPConstants.SQLQueries.GET_JWT_DETAIL);

            jwtStorageManager.getJwtsFromDB("jti", 1);
        }
    }

    @Test(priority = 5, expectedExceptions = IdentityOAuth2Exception.class)
    public void testPersistJWTIdInDBWithSQLException() throws Exception {

        try (MockedStatic<IdentityDatabaseUtil> ignored = mockStaticDBUtils("execute",
                new SQLException("Test Exception"))) {

            mockUtils.when(Utils::isTenantIdColumnAvailableInIdnOidcAuth)
                    .thenReturn(true);
            mockUtils.when(() -> Utils.getDBQuery(DPoPConstants.INSERT_JWD_ID))
                    .thenReturn(DPoPConstants.SQLQueries.INSERT_TENANTED_JWD_ID);

            jwtStorageManager.persistJWTIdInDB("fail-test-jti", 1,
                    System.currentTimeMillis() + 3600000, System.currentTimeMillis());
        }
    }

    private MockedStatic<IdentityDatabaseUtil> mockStaticDBUtils(String method, SQLException exceptionToThrow)
            throws SQLException {

        Connection mockConnection = mock(Connection.class);
        PreparedStatement mockPreparedStatement = mock(PreparedStatement.class);

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);

        if ("executeQuery".equals(method)) {
            doThrow(exceptionToThrow).when(mockPreparedStatement).executeQuery();
        } else if ("executeUpdate".equals(method)) {
            doThrow(exceptionToThrow).when(mockPreparedStatement).executeUpdate();
        }

        MockedStatic<IdentityDatabaseUtil> mockedDbUtil = mockStatic(IdentityDatabaseUtil.class);
        mockedDbUtil.when(() ->
                IdentityDatabaseUtil.getDBConnection(false)).thenReturn(mockConnection);
        mockedDbUtil.when(() ->
                IdentityDatabaseUtil.getDBConnection(true)).thenReturn(mockConnection);

        return mockedDbUtil;
    }
}
