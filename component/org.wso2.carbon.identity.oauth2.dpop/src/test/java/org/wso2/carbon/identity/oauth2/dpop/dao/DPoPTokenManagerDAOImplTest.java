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
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dpop.util.Utils;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

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
}
