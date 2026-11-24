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

package org.wso2.carbon.identity.oauth2.dpop.dao;

/**
 * SQL queries for DPoP related DB operations.
 */
public class SQLQueries {

    /**
     * @deprecated Joins every access token row of the refresh token. Use the
     * {@code RETRIEVE_TOKEN_BINDING_OF_ONE_ACCESS_TOKEN_BY_REFRESH_TOKEN_HASH} query of the database instead.
     */
    @Deprecated
    public static final String RETRIEVE_TOKEN_BINDING_BY_REFRESH_TOKEN_HASH =
            "SELECT BINDING.TOKEN_BINDING_TYPE,BINDING.TOKEN_BINDING_VALUE,BINDING.TOKEN_BINDING_REF " +
                    "FROM IDN_OAUTH2_ACCESS_TOKEN TOKEN LEFT JOIN IDN_OAUTH2_TOKEN_BINDING BINDING ON " +
                    "TOKEN.TOKEN_ID=BINDING.TOKEN_ID WHERE TOKEN.REFRESH_TOKEN_HASH = ? " +
                    "AND BINDING.TOKEN_BINDING_TYPE = ?";

    /*
     * Every access token row that shares a refresh token hash belongs to the same refresh token, and a refresh copies
     * the binding of the previous row to the new one. So the binding of any one row is the binding of the refresh
     * token. Read the binding of one row instead of joining all of them: when the refresh token is not renewed, each
     * refresh adds a row with the same hash.
     */
    private static final String TOKEN_BINDING_BY_TOKEN_ID =
            "SELECT BINDING.TOKEN_BINDING_TYPE,BINDING.TOKEN_BINDING_VALUE,BINDING.TOKEN_BINDING_REF " +
                    "FROM IDN_OAUTH2_TOKEN_BINDING BINDING WHERE BINDING.TOKEN_ID = ";
    private static final String AND_TOKEN_BINDING_TYPE = " AND BINDING.TOKEN_BINDING_TYPE = ?";

    public static final String RETRIEVE_TOKEN_BINDING_OF_ONE_ACCESS_TOKEN_BY_REFRESH_TOKEN_HASH =
            TOKEN_BINDING_BY_TOKEN_ID +
                    "(SELECT TOKEN_ID FROM IDN_OAUTH2_ACCESS_TOKEN WHERE REFRESH_TOKEN_HASH = ? LIMIT 1)" +
                    AND_TOKEN_BINDING_TYPE;

    public static final String RETRIEVE_TOKEN_BINDING_OF_ONE_ACCESS_TOKEN_BY_REFRESH_TOKEN_HASH_MSSQL =
            TOKEN_BINDING_BY_TOKEN_ID +
                    "(SELECT TOP 1 TOKEN_ID FROM IDN_OAUTH2_ACCESS_TOKEN WHERE REFRESH_TOKEN_HASH = ?)" +
                    AND_TOKEN_BINDING_TYPE;

    public static final String RETRIEVE_TOKEN_BINDING_OF_ONE_ACCESS_TOKEN_BY_REFRESH_TOKEN_HASH_DB2 =
            TOKEN_BINDING_BY_TOKEN_ID +
                    "(SELECT TOKEN_ID FROM IDN_OAUTH2_ACCESS_TOKEN WHERE REFRESH_TOKEN_HASH = ? " +
                    "FETCH FIRST 1 ROWS ONLY)" +
                    AND_TOKEN_BINDING_TYPE;

    public static final String RETRIEVE_TOKEN_BINDING_OF_ONE_ACCESS_TOKEN_BY_REFRESH_TOKEN_HASH_ORACLE =
            TOKEN_BINDING_BY_TOKEN_ID +
                    "(SELECT TOKEN_ID FROM IDN_OAUTH2_ACCESS_TOKEN WHERE REFRESH_TOKEN_HASH = ? AND ROWNUM < 2)" +
                    AND_TOKEN_BINDING_TYPE;

    public static final String RETRIEVE_TOKEN_BINDING_BY_REFRESH_TOKEN_HASH_NON_PERSISTENT_ACCESS_TOKEN =
            "SELECT BINDING.TOKEN_BINDING_TYPE,BINDING.TOKEN_BINDING_VALUE,BINDING.TOKEN_BINDING_REF " +
                    "FROM IDN_OAUTH2_REFRESH_TOKEN TOKEN LEFT JOIN IDN_OAUTH2_REFRESH_TOKEN_BINDING BINDING ON " +
                    "TOKEN.REFRESH_TOKEN_ID=BINDING.REFRESH_TOKEN_ID WHERE TOKEN.REFRESH_TOKEN_HASH = ? " +
                    "AND BINDING.TOKEN_BINDING_TYPE = ?";

    public static final String RETRIEVE_AUTHORIZATION_CODE_BY_CODE_ID =
            "SELECT AUTHORIZATION_CODE FROM IDN_OAUTH2_AUTHORIZATION_CODE WHERE CODE_ID = ?";

    public static final String INSERT_DPOP_JKT = "INSERT INTO IDN_OAUTH2_DPOP_JKT (CODE_ID, DPOP_JKT) VALUES (?, ?)";

    public static final String RETRIEVE_DPOP_JKT_BY_AUTHORIZATION_CODE = "SELECT DPOP_JKT FROM IDN_OAUTH2_DPOP_JKT " +
            "WHERE CODE_ID = (SELECT CODE_ID FROM IDN_OAUTH2_AUTHORIZATION_CODE WHERE AUTHORIZATION_CODE_HASH = ?)";
}
