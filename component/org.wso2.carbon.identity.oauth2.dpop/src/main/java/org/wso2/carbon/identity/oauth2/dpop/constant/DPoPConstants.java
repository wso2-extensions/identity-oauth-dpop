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

package org.wso2.carbon.identity.oauth2.dpop.constant;

/**
 * This class defines constants for Oauth2 DPoP validation.
 */
public class DPoPConstants {

    public static final String VALIDITY_PERIOD = "header_validity_period";
    public static final int DEFAULT_HEADER_VALIDITY = 60000;
    public static final String DPOP_EVENT_HANDLER_NAME = "dpopEventHandler";
    public static final String DPOP_ISSUED_AT = "iat";
    public static final String DPOP_HTTP_URI = "htu";
    public static final String DPOP_HTTP_METHOD = "htm";
    public static final String DPOP_ACCESS_TOKEN_HASH = "ath";
    public static final String DPOP_JWT_TYPE = "dpop+jwt";
    public static final String DPOP_TOKEN_TYPE = "DPoP";
    public static final String EXPIRED_DPOP_PROOF = "Expired DPoP Proof";
    public static final String INVALID_DPOP_PROOF = "invalid_dpop_proof";
    public static final String INVALID_DPOP_ERROR = "Invalid DPoP Proof";
    public static final String INVALID_CLIENT = "invalid_client";
    public static final String INVALID_CLIENT_ERROR = "Invalid Client";
    public static final String ECDSA_ENCRYPTION = "EC";
    public static final String RSA_ENCRYPTION = "RSA";
    public static final String HTTP_METHOD = "httpMethod";
    public static final String HTTP_POST = "POST";
    public static final String HTTP_URL = "httpUrl";
    public static final String JTI = "jti";
    public static final String OAUTH_DPOP_HEADER = "DPoP";
    public static final String CNF = "cnf";
    public static final String TOKEN_TYPE = "token_type";
    public static final String JWK_THUMBPRINT = "jkt";
    public static final String DPOP_JKT_TABLE_NAME = "IDN_OAUTH2_DPOP_JKT";
    public static final String DPOP_JKT = "dpop_jkt";
    public static final String AUTHORIZATION_HEADER = "authorization";
    public static final String CLIENT_ID = "client_id";
    public static final String AUTHORIZATION_CODE_GRANT_TYPE = "authorization_code";
    public static final String OAUTH_REVOKE_ENDPOINT = "/oauth2/revoke";
    public static final String SKIP_DPOP_VALIDATION_IN_REVOKE = "skip_dpop_validation_in_revoke";
    public static final boolean DEFAULT_SKIP_DPOP_VALIDATION_IN_REVOKE_VALUE = true;
    public static final String DPOP_PROOF_REPLAYED = "DPoP Proof has been replayed";

    // DPoP JTI persistence related keys
    public static final String GET_JWT_ID = "GET_JWT_ID";
    public static final String GET_JWT = "GET_JWT";
    public static final String GET_JWT_DETAILS = "GET_JWT_DETAILS";
    public static final String INSERT_JWD_ID = "INSERT_JWD_ID";
    public static final int DEFAULT_TENANT_ID = -1;

    /**
     * SQL Queries for the JWT ID persistence.
     */
    public static class SQLQueries {

        public static final String TENANT_ID = "TENANT_ID";
        public static final String IDN_OIDC_JTI = "IDN_OIDC_JTI";
        public static final String EXP_TIME = "EXP_TIME";
        public static final String TIME_CREATED = "TIME_CREATED";
        public static final String INSERT_JWD_ID = "INSERT INTO IDN_OIDC_JTI (JWT_ID, EXP_TIME, TIME_CREATED)" +
                "VALUES (?,?,?)";
        public static final String INSERT_TENANTED_JWD_ID = "INSERT INTO IDN_OIDC_JTI (JWT_ID, TENANT_ID, EXP_TIME, " +
                "TIME_CREATED) VALUES (?,?,?,?)";

        public static final String GET_JWT = "SELECT EXP_TIME,TIME_CREATED FROM IDN_OIDC_JTI WHERE JWT_ID =?";

        public static final String GET_JWT_ID = "SELECT 1 FROM IDN_OIDC_JTI WHERE JWT_ID =?";

        public static final String GET_TENANTED_JWT_ID = "SELECT 1 FROM IDN_OIDC_JTI WHERE JWT_ID =? AND TENANT_ID=?";

        public static final String GET_JWT_DETAIL = "SELECT TENANT_ID, EXP_TIME,TIME_CREATED FROM IDN_OIDC_JTI WHERE " +
                "JWT_ID =? AND TENANT_ID IN (?,?)";
    }
}
