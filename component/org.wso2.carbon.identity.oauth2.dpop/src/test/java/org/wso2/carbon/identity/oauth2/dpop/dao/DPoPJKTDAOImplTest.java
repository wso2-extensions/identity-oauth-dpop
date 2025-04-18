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

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

 /**
 * Test class for {@link DPoPJKTDAOImpl}.
 */
@WithH2Database(files = {"dbScripts/h2.sql"})
@WithCarbonHome
public class DPoPJKTDAOImplTest {

    private static final String CONSUMER_KEY = "sampleConsumerKey";
    private static final String DPOP_JKT = "sampleDpopJkt";
    private static final String CODE_ID = "sampleCodeId";
    private static final String AUTHZ_CODE = "123456712638";

    private DPoPJKTDAOImpl dao;

    @BeforeClass
    public void setUp() {
        dao = new DPoPJKTDAOImpl();
    }

    @Test
    public void testInsertDPoPJKT() throws Exception {

        try {
            dao.insertDPoPJKT(CONSUMER_KEY, CODE_ID, DPOP_JKT);
        } catch (Exception e) {
            Assert.fail();
        }

        String result = dao.getDPoPJKTFromAuthzCode(AUTHZ_CODE);

        Assert.assertEquals(result, DPOP_JKT);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testInsertEmptyDPoPJKT() throws Exception {

        dao.insertDPoPJKT("", "", "");
    }

    @Test
    public void testGetAthorizationCode() throws Exception {

        String result = dao.getAuthzCodeFromCodeId(CODE_ID);
        Assert.assertEquals(result, AUTHZ_CODE);
    }

    @Test
    public void testGetDPoPJKTFromUnknownAuthzCode() throws Exception {

        String result = dao.getDPoPJKTFromAuthzCode("unknownCode");
        Assert.assertNull(result, "Expected null for unknown authorization code");
    }
}
