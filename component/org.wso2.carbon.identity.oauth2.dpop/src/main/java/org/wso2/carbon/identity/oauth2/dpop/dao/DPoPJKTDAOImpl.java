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

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.tokenprocessor.HashingPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Implementation of DPoPJKTDAO interface.
 */
public class DPoPJKTDAOImpl implements DPoPJKTDAO {

    private static final Log LOG = LogFactory.getLog(DPoPJKTDAOImpl.class);
    private static TokenPersistenceProcessor hashingPersistenceProcessor;

    public DPoPJKTDAOImpl() {

        hashingPersistenceProcessor = new HashingPersistenceProcessor();
    }
    @Override
    public void insertDPoPJKT(String consumerKey, String codeId, String dpopJkt) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Persisting dpop_jkt: " + DigestUtils.sha256Hex(dpopJkt) + " for client: "
                    + consumerKey);
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        try {
            String sql = SQLQueries.INSERT_DPOP_JKT;
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, codeId);
            prepStmt.setString(2, dpopJkt);
            prepStmt.execute();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error when persisting the dpop_jkt for consumer key : "
                    + consumerKey, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }

    }

    @Override
    public String getDPoPJKTFromAuthzCode(String authzCode) throws IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        try {
            String sql = SQLQueries.RETRIEVE_DPOP_JKT_BY_AUTHORIZATION_CODE;
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, hashingPersistenceProcessor.getProcessedAuthzCode(authzCode));
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                String dpopJkt = resultSet.getString("DPOP_JKT");
                //ensures the function returns null only when there is no entry in DB for the given authzCode
                return (dpopJkt == null) ? "" : dpopJkt;
            }
            return null;
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error when retrieving dpop_jkt for consumer key : " + authzCode, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    @Override
    public String getAuthzCodeFromCodeId(String codeId) throws IdentityOAuth2Exception {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        try {
            String sql = SQLQueries.RETRIEVE_AUTHORIZATION_CODE_BY_CODE_ID;
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, codeId);
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                return resultSet.getString("AUTHORIZATION_CODE");
            }
            return null;
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error when retrieving authorization code for code id : " + codeId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }
}
