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
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.HashingPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dpop.util.Utils;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

 /**
 * Test class for {@link DPoPTokenManagerDAOImpl}.
 */
@WithH2Database(files = {"dbScripts/h2.sql"})
@WithCarbonHome
public class DPoPTokenManagerDAOImplTest {

    private static final String TEST_REFRESH_TOKEN = "bde76f62-d955-381a-be3b-5adf16abae44";
    private static final String BINDING_TYPE = "DPoP";
    private static final String BINDING_VALUE = "sampleBindingValue";
    private static final String BINDING_REF = "bindRef123";

    private MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration;
    private DPoPTokenManagerDAOImpl dao;

    @BeforeClass
    public void setUp() {

        dao = new DPoPTokenManagerDAOImpl();
    }

    @BeforeMethod
    public void init() {

        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        oAuthServerConfiguration = mockStatic(OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        oAuthServerConfiguration.when(() -> OAuthServerConfiguration.getInstance().getHashAlgorithm()).
                thenReturn("SHA-256");
    }

    @AfterMethod
    public void tearDown() {

        oAuthServerConfiguration.close();
    }

    @Test
    public void testGetTokenBindingUsingHashSuccess() throws Exception {

        try (MockedStatic<Utils> utilsMock = mockStatic(Utils.class)) {

            JdbcTemplate jdbcTemplate = new JdbcTemplate(IdentityDatabaseUtil.getDataSource());
            utilsMock.when(Utils::getNewTemplate).thenReturn(jdbcTemplate);


            TokenBinding result = dao.getTokenBindingUsingHash(TEST_REFRESH_TOKEN);

            Assert.assertNotNull(result);
            Assert.assertEquals(result.getBindingType(), BINDING_TYPE);
            Assert.assertEquals(result.getBindingValue(), BINDING_VALUE);
            Assert.assertEquals(result.getBindingReference(), BINDING_REF);
        }
    }

    @Test
    public void testGetTokenBindingUsingHashNotFound() throws Exception {

        try (MockedStatic<Utils> utilsMock = mockStatic(Utils.class)) {

            JdbcTemplate jdbcTemplate = new JdbcTemplate(IdentityDatabaseUtil.getDataSource());
            utilsMock.when(Utils::getNewTemplate).thenReturn(jdbcTemplate);


            TokenBinding result = dao.getTokenBindingUsingHash("nonExistentToken");

            Assert.assertNull(result, "Expected null when token binding not found.");
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetTokenBindingUsingHashWithNullToken() throws Exception {

        dao.getTokenBindingUsingHash(null);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetTokenBindingUsingHashWithSQLException() throws Exception {

        try (MockedStatic<Utils> utilsMock = mockStatic(Utils.class)) {

            JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
            utilsMock.when(Utils::getNewTemplate).thenReturn(jdbcTemplate);

            doThrow(new DataAccessException("Simulated SQL exception"))
                    .when(jdbcTemplate).executeQuery(Mockito.anyString(), Mockito.any(), Mockito.any());
            dao.getTokenBindingUsingHash(TEST_REFRESH_TOKEN);
        }
    }

    @Test
    public void testGetTokenBindingUsingHashForRefreshTokenWithManyAccessTokens() throws Exception {

        // When the refresh token is not renewed, every refresh adds an access token row with the same refresh token
        // hash and copies the binding forward.
        String refreshToken = "renewal-off-dpop-refresh-token";
        insertRefreshTokenLineage(refreshToken, "dpop-lineage-", 3, BINDING_TYPE);
        enableAccessTokenPersistence();
        try (MockedStatic<Utils> utilsMock = mockStatic(Utils.class)) {
            utilsMock.when(Utils::getNewTemplate).thenReturn(new JdbcTemplate(IdentityDatabaseUtil.getDataSource()));

            TokenBinding result = dao.getTokenBindingUsingHash(refreshToken);

            Assert.assertNotNull(result);
            Assert.assertEquals(result.getBindingType(), BINDING_TYPE);
            Assert.assertEquals(result.getBindingValue(), "dpop-lineage-value");
            Assert.assertEquals(result.getBindingReference(), "dpop-lineage-ref");
        } finally {
            deleteRefreshTokenLineage(refreshToken);
        }
    }

    @Test
    public void testGetTokenBindingUsingHashForNonDPoPRefreshTokenWithManyAccessTokens() throws Exception {

        String refreshToken = "renewal-off-sso-session-refresh-token";
        insertRefreshTokenLineage(refreshToken, "sso-lineage-", 3, "sso-session");
        enableAccessTokenPersistence();
        try (MockedStatic<Utils> utilsMock = mockStatic(Utils.class)) {
            utilsMock.when(Utils::getNewTemplate).thenReturn(new JdbcTemplate(IdentityDatabaseUtil.getDataSource()));

            Assert.assertNull(dao.getTokenBindingUsingHash(refreshToken),
                    "Expected null when the refresh token is not DPoP bound.");
        } finally {
            deleteRefreshTokenLineage(refreshToken);
        }
    }

    private void enableAccessTokenPersistence() {

        OAuthServerConfiguration config = OAuthServerConfiguration.getInstance();
        when(config.isAccessTokenPersistenceEnabled()).thenReturn(true);
    }

    private void insertRefreshTokenLineage(String refreshToken, String prefix, int count, String bindingType)
            throws Exception {

        String refreshTokenHash = new HashingPersistenceProcessor().getProcessedRefreshToken(refreshToken);
        try (Connection connection = IdentityDatabaseUtil.getDataSource().getConnection();
             PreparedStatement tokenStatement = connection.prepareStatement("INSERT INTO IDN_OAUTH2_ACCESS_TOKEN " +
                     "(TOKEN_ID, ACCESS_TOKEN, REFRESH_TOKEN, CONSUMER_KEY_ID, AUTHZ_USER, TENANT_ID, USER_DOMAIN, " +
                     "USER_TYPE, GRANT_TYPE, TIME_CREATED, REFRESH_TOKEN_TIME_CREATED, TOKEN_SCOPE_HASH, " +
                     "TOKEN_STATE, TOKEN_STATE_ID, REFRESH_TOKEN_HASH, TOKEN_BINDING_REF) " +
                     "VALUES (?, ?, ?, 1, ?, 1, 'PRIMARY', 'APPLICATION_USER', 'refresh_token', ?, ?, 'scopeHash', " +
                     "?, ?, ?, ?)");
             PreparedStatement bindingStatement = connection.prepareStatement("INSERT INTO IDN_OAUTH2_TOKEN_BINDING " +
                     "(TOKEN_ID, TOKEN_BINDING_TYPE, TOKEN_BINDING_REF, TOKEN_BINDING_VALUE, TENANT_ID) " +
                     "VALUES (?, ?, ?, ?, 1)")) {
            for (int i = 0; i < count; i++) {
                boolean latest = i == count - 1;
                String tokenId = prefix + i;
                tokenStatement.setString(1, tokenId);
                tokenStatement.setString(2, prefix + "access-" + i);
                tokenStatement.setString(3, refreshToken);
                tokenStatement.setString(4, prefix + "user");
                Timestamp timeCreated = new Timestamp(System.currentTimeMillis() - (count - i) * 1000L);
                tokenStatement.setTimestamp(5, timeCreated);
                tokenStatement.setTimestamp(6, timeCreated);
                tokenStatement.setString(7, latest ? "ACTIVE" : "EXPIRED");
                tokenStatement.setString(8, latest ? "NONE" : prefix + "state-" + i);
                tokenStatement.setString(9, refreshTokenHash);
                tokenStatement.setString(10, prefix + "ref");
                tokenStatement.executeUpdate();

                bindingStatement.setString(1, tokenId);
                bindingStatement.setString(2, bindingType);
                bindingStatement.setString(3, prefix + "ref");
                bindingStatement.setString(4, prefix + "value");
                bindingStatement.executeUpdate();
            }
            if (!connection.getAutoCommit()) {
                connection.commit();
            }
        }
    }

    private void deleteRefreshTokenLineage(String refreshToken) throws Exception {

        String refreshTokenHash = new HashingPersistenceProcessor().getProcessedRefreshToken(refreshToken);
        try (Connection connection = IdentityDatabaseUtil.getDataSource().getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "DELETE FROM IDN_OAUTH2_ACCESS_TOKEN WHERE REFRESH_TOKEN_HASH = ?")) {
            statement.setString(1, refreshTokenHash);
            statement.executeUpdate();
            if (!connection.getAutoCommit()) {
                connection.commit();
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Could not clean up the test refresh token rows.", e);
        }
    }
}
