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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.dpop.util.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;

import static org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants.DEFAULT_TENANT_ID;
import static org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants.GET_JWT;
import static org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants.GET_JWT_DETAILS;
import static org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants.SQLQueries.EXP_TIME;
import static org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants.SQLQueries.TENANT_ID;
import static org.wso2.carbon.identity.oauth2.dpop.constant.DPoPConstants.SQLQueries.TIME_CREATED;

/**
 * This class is used to store and retrieve the JWT ID from the database.
 */
public class JWTStorageManager {

    private static final Log log = LogFactory.getLog(JWTStorageManager.class);

    public List<JWTEntry> getJwtsFromDB(String jti, int tenantId) throws IdentityOAuth2Exception {

        List<JWTEntry> jwtEntries = new ArrayList<>();
        String query = Utils.isTenantIdColumnAvailableInIdnOidcAuth()
                ? Utils.getDBQuery(GET_JWT_DETAILS)
                : Utils.getDBQuery(GET_JWT);

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement prepStmt = connection.prepareStatement(query)) {

            prepStmt.setString(1, jti);
            Calendar utcCalendar = Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC));

            if (Utils.isTenantIdColumnAvailableInIdnOidcAuth()) {
                prepStmt.setInt(2, tenantId);
                prepStmt.setInt(3, DEFAULT_TENANT_ID);
            }

            try (ResultSet rs = prepStmt.executeQuery()) {
                while (rs.next()) {
                    long exp = rs.getTimestamp(EXP_TIME, utcCalendar).getTime();
                    long created = rs.getTimestamp(TIME_CREATED, utcCalendar).getTime();

                    if (Utils.isTenantIdColumnAvailableInIdnOidcAuth()) {
                        int tenantID = rs.getInt(TENANT_ID);
                        jwtEntries.add(new JWTEntry(exp, created, tenantID));
                    } else {
                        jwtEntries.add(new JWTEntry(exp, created));
                    }
                }
            }

        } catch (SQLException e) {
            log.error("Error retrieving JWT ID: " + jti + ", tenant ID: " + tenantId, e);
            throw new IdentityOAuth2Exception("Error retrieving JWT entries for JTI: " + jti, e);
        }

        return jwtEntries;
    }

    public void persistJWTIdInDB(String jti, int tenantId, long expTime, long timeCreated)
            throws IdentityOAuth2Exception {

        String query = Utils.getDBQuery(DPoPConstants.INSERT_JWD_ID);
        boolean isTenantColumnAvailable = Utils.isTenantIdColumnAvailableInIdnOidcAuth();

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true);
             PreparedStatement preparedStatement = connection.prepareStatement(query)) {

            Timestamp issuedAt = new Timestamp(timeCreated);
            Timestamp expiry = new Timestamp(expTime);
            Calendar utcCalendar = Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC));

            int paramIndex = 1;
            preparedStatement.setString(paramIndex++, jti);

            if (isTenantColumnAvailable) {
                preparedStatement.setInt(paramIndex++, tenantId);
            }

            preparedStatement.setTimestamp(paramIndex++, expiry, utcCalendar);
            preparedStatement.setTimestamp(paramIndex, issuedAt, utcCalendar);

            int rowsAffected = preparedStatement.executeUpdate();
            if (rowsAffected > 0) {
                connection.commit();
            } else {
                throw new IdentityOAuth2Exception("Failed to insert JWT ID: " + jti + ". No rows affected.");
            }

        } catch (SQLException e) {
            String error = String.format("Error storing JWT ID '%s' (exp: %d)", jti, expTime);
            log.error(error, e);
            throw new IdentityOAuth2Exception("Error persisting JWT ID in database for: " + jti, e);
        }
    }
}
