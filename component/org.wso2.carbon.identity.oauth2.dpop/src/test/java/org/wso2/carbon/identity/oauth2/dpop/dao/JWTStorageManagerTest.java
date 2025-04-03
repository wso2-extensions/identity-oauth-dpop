package org.wso2.carbon.identity.oauth2.dpop.dao;

import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.lang.StringUtils;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.dpop.util.Utils;

import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

@WithH2Database(files = {"dbscripts/h2.sql"})
public class JWTStorageManagerTest {

    private static final Map<String, BasicDataSource> dataSourceMap = new HashMap<>();

    private JWTStorageManager jwtStorageManager;

    private static final String DB_NAME = "testJWTStorageManager";

    private MockedStatic<Utils> mockUtils;

    @BeforeClass
    public void setUp() throws Exception {

        jwtStorageManager = new JWTStorageManager();
        initiateH2Base(getFilePath("h2.sql"));
    }

    @BeforeMethod
    public void init() throws Exception {

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

        try (Connection connection = getConnection(DB_NAME);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            prepareConnection(connection, false, identityDatabaseUtil);

            mockUtils.when(Utils::isTenantIdColumnAvailableInIdnOidcAuth)
                    .thenReturn(false);

            mockUtils.when(() -> Utils.getDBQuery(DPoPConstants.GET_JWT))
                    .thenReturn(DPoPConstants.SQLQueries.GET_JWT);

            List<JWTEntry> results = jwtStorageManager.getJwtsFromDB("jti", 1);
            assertTrue(results.isEmpty(), "Expected empty result set");
        }

    }

    @Test(priority = 2)
    public void persistJTIinDB() throws Exception {

        try (Connection connection = getConnection(DB_NAME);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            prepareConnection(connection, true, identityDatabaseUtil);

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
    }

    @Test(priority = 3)
    public void testGetJwtsFromDB() throws Exception {

        try (Connection connection = getConnection(DB_NAME);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            prepareConnection(connection, false, identityDatabaseUtil);

            mockUtils.when(Utils::isTenantIdColumnAvailableInIdnOidcAuth)
                    .thenReturn(true);

            mockUtils.when(() -> Utils.getDBQuery(DPoPConstants.GET_JWT_DETAILS))
                    .thenReturn(DPoPConstants.SQLQueries.GET_JWT_DETAIL);

            List<JWTEntry> results = jwtStorageManager.getJwtsFromDB("test-jti-123", 1);
            assertEquals(results.size(), 1, "Expected result set size of 1");
        }
    }

    @Test(priority = 4, expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetJwtsFromDBWithSQLException() throws Exception {

        try (Connection connection = getConnection(DB_NAME);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {

            prepareConnection(connection, false, identityDatabaseUtil);

            mockUtils.when(Utils::isTenantIdColumnAvailableInIdnOidcAuth)
                    .thenReturn(true);
            mockUtils.when(() -> Utils.getDBQuery(DPoPConstants.GET_JWT_DETAILS))
                    .thenReturn(DPoPConstants.SQLQueries.GET_JWT_DETAIL);

            connection.close();

            jwtStorageManager.getJwtsFromDB("jti", 1);
        }
    }

    @Test(priority = 5, expectedExceptions = IdentityOAuth2Exception.class)
    public void testPersistJWTIdInDBNoRowsAffected() throws Exception {

        try (Connection connection = getConnection(DB_NAME);
             MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {

            prepareConnection(connection, true, identityDatabaseUtil);

            mockUtils.when(Utils::isTenantIdColumnAvailableInIdnOidcAuth)
                    .thenReturn(true);
            mockUtils.when(() -> Utils.getDBQuery(DPoPConstants.INSERT_JWD_ID))
                    .thenReturn(DPoPConstants.SQLQueries.INSERT_TENANTED_JWD_ID);

            connection.close();

            jwtStorageManager.persistJWTIdInDB("fail-test-jti", 1,
                    System.currentTimeMillis() + 3600000, System.currentTimeMillis());
        }
    }

    private void prepareConnection(Connection connection, boolean shouldApplyTransaction,
                                   MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil) {

        identityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(shouldApplyTransaction))
                .thenReturn(connection);
    }

    public static Connection getConnection(String database) throws SQLException {

        if (dataSourceMap.get(database) != null) {
            return dataSourceMap.get(database).getConnection();
        }
        throw new RuntimeException("No datasource initiated for database: " + database);
    }


    protected void initiateH2Base(String scriptPath) throws Exception {

        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUsername("username");
        dataSource.setPassword("password");
        dataSource.setUrl("jdbc:h2:mem:test" + JWTStorageManagerTest.DB_NAME);
        try (Connection connection = dataSource.getConnection()) {
            connection.createStatement().executeUpdate("RUNSCRIPT FROM '" + scriptPath + "'");
        }
        dataSourceMap.put(JWTStorageManagerTest.DB_NAME, dataSource);
    }

    public static String getFilePath(String fileName) {

        if (StringUtils.isNotBlank(fileName)) {
            return Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "dbScripts", fileName)
                    .toString();
        }
        throw new IllegalArgumentException("DB Script file name cannot be empty.");
    }
}
