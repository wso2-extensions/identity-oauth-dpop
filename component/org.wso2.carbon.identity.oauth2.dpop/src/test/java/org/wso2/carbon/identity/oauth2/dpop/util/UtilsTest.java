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

package org.wso2.carbon.identity.oauth2.dpop.util;

import com.nimbusds.jose.Requirement;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Date;

import javax.sql.DataSource;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.DUMMY_CLIENT_ID;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.DUMMY_DPOP_PROOF;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.DUMMY_HTTP_METHOD;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.DUMMY_HTTP_URL;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.DUMMY_JTI;
import static org.wso2.carbon.identity.oauth2.dpop.util.DPoPTestConstants.DUMMY_TENANT_DOMAIN;

@WithCarbonHome
public class UtilsTest {

    @Mock
    DataSource mockDataSource;

    @Mock
    JWK mockJWK;

    @Mock
    private OAuthAppDO mockOAuthAppDO;

    private AutoCloseable closeable;

    @BeforeMethod
    public void setUp() {

        closeable = MockitoAnnotations.openMocks(this);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        closeable.close();
    }

    @Test
    public void testGetNewTemplate() {
        try (MockedStatic<IdentityDatabaseUtil> mockedIdentityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class)) {
            mockedIdentityDatabaseUtil.when(IdentityDatabaseUtil::getDataSource).thenReturn(mockDataSource);
            try (MockedConstruction<JdbcTemplate> mockJdbcTemplate = Mockito.mockConstruction(JdbcTemplate.class,
                    (mock, context) -> { })) {
                assertEquals(Utils.getNewTemplate(), mockJdbcTemplate.constructed().get(0));
            }
        }
    }

    @DataProvider(name = "dpopProofProvider")
    public Object[][] dpopProofProvider() throws Exception {

        return new Object[][]{
                {DPoPProofUtil.genarateDPoPProof("RSA", DUMMY_JTI, DUMMY_HTTP_METHOD, DUMMY_HTTP_URL, new Date()),
                        DPoPProofUtil.RSA_DPOP_JWK_THUMBPRINT},
                {DPoPProofUtil.genarateDPoPProof("EC", DUMMY_JTI, DUMMY_HTTP_METHOD, DUMMY_HTTP_URL, new Date()),
                        DPoPProofUtil.EC_DPOP_JWK_THUMBPRINT},
                {DUMMY_DPOP_PROOF, StringUtils.EMPTY},
        };
    }

    @Test(dataProvider = "dpopProofProvider")
    public void testGetThumbprintOfKeyFromDpopProof(String dpopProof, String expectedResult) {

        try {
            String thumbprint = Utils.getThumbprintOfKeyFromDpopProof(dpopProof);
            assertEquals(thumbprint, expectedResult);
        } catch (IdentityOAuth2Exception e) {
            assertEquals(e.getErrorCode(), DPoPConstants.INVALID_DPOP_PROOF);
            assertEquals(e.getMessage(), DPoPConstants.INVALID_DPOP_ERROR);
        }
    }

    @Test
    public void testGetThumbprintOfKeyFromDpopProofWithInvalidJWK() throws Exception {

        try (MockedStatic<JWK> mockedJWK = mockStatic(JWK.class, CALLS_REAL_METHODS)) {
            mockedJWK.when(() -> JWK.parse(anyString())).thenReturn(mockJWK);
            when(mockJWK.getKeyType()).thenReturn(new KeyType("some_type", Requirement.REQUIRED));
            String dPoPProof = DPoPProofUtil.genarateDPoPProof();
            assertEquals(Utils.getThumbprintOfKeyFromDpopProof(dPoPProof), StringUtils.EMPTY);
        }
    }

    @Test
    public void testGetApplicationBindingType() throws Exception {

        try (MockedStatic<OAuth2Util> oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class)) {
            oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString())).
                    thenReturn(mockOAuthAppDO);
            Utils.getApplicationBindingType(DUMMY_CLIENT_ID, DUMMY_TENANT_DOMAIN);
        }
    }
}
