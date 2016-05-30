/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.data.publisher.application.authentication.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.databridge.commons.Event;
import org.wso2.carbon.identity.application.authentication.framework.AbstractAuthenticationDataPublisher;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationData;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthPublisherConstants;
import org.wso2.carbon.identity.data.publisher.application.authentication.internal.AuthenticationDataPublisherDataHolder;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

public class DASAuthnDataPublisherImpl extends AbstractAuthenticationDataPublisher {

    public static final Log LOG = LogFactory.getLog(DASAuthnDataPublisherImpl.class);
    public static final String DAS_PUBLISHER_NAME = "DAS_AUTHN_DATA_PUBLISHER";

    @Override
    public void doPublishAuthenticationStepSuccess(AuthenticationData authenticationData) {

        publishAuthenticationData(authenticationData);
    }

    @Override
    public void doPublishAuthenticationStepFailure(AuthenticationData authenticationData) {

        publishAuthenticationData(authenticationData);
    }

    @Override
    public void doPublishAuthenticationSuccess(AuthenticationData authenticationData) {

        publishAuthenticationData(authenticationData);
    }

    @Override
    public void doPublishAuthenticationFailure(AuthenticationData authenticationData) {

        publishAuthenticationData(authenticationData);
    }

    @Override
    public void doPublishSessionCreation(String user, String userStoreDomain, String tenantDomain, String sessionId,
                                         long timestamp, boolean isRememberMe) {

    }

    @Override
    public void doPublishSessionTermination(String user, String userStoreDomain, String tenantDomain, String sessionId,
                                            long timestamp, boolean isRememberMe) {

    }

    private void publishAuthenticationData(AuthenticationData authenticationData) {

        String roleList = getCommaSeparatedUserRoles(authenticationData.getUserStoreDomain + "/" +
                authenticationData.getUsername(), authenticationData.getTenantDomain());

        Object[] payloadData = new Object[20];
        payloadData[0] = authenticationData.getContextId();
        payloadData[1] = authenticationData.getEventId();
        payloadData[2] = authenticationData.isAuthnSuccess();
        payloadData[3] = authenticationData.getUsername();
        payloadData[4] = authenticationData.getUserStoreDomain();
        payloadData[5] = authenticationData.getTenantDomain();
        payloadData[6] = authenticationData.getRemoteIp();
        payloadData[7] = authenticationData.getInboundProtocol();
        payloadData[8] = authenticationData.getServiceProvider();
        payloadData[9] = authenticationData.isRememberMe();
        payloadData[10] = authenticationData.isForcedAuthn();
        payloadData[11] = authenticationData.isPassive();
        payloadData[12] = roleList;
        payloadData[13] = String.valueOf(authenticationData.getStepNo());
        payloadData[14] = authenticationData.getIdentityProvider();
        payloadData[15] = authenticationData.isSuccess();
        payloadData[16] = authenticationData.getAuthenticator();
        payloadData[17] = authenticationData.isInitialLogin();
        payloadData[18] = authenticationData.isFederated();
        payloadData[19] = System.currentTimeMillis();
        Event event = new Event(AuthPublisherConstants.AUTHN_DATA_STREAM_NAME, System.currentTimeMillis(), null, null,
                payloadData);
        AuthenticationDataPublisherDataHolder.getInstance().getPublisherService().publish(event);
    }

    @Override
    public String getName() {

        return DAS_PUBLISHER_NAME;
    }

    private String getCommaSeparatedUserRoles(String userName, String tenantDomain) {

        if (tenantDomain == null || userName == null) {
            return StringUtils.EMPTY;
        }

        RegistryService registryService = AuthenticationDataPublisherDataHolder.getInstance().getRegistryService();
        RealmService realmService = AuthenticationDataPublisherDataHolder.getInstance().getRealmService();

        UserRealm realm = null;
        UserStoreManager userstore = null;

        try {
            realm = AnonymousSessionUtil.getRealmByTenantDomain(registryService,
                    realmService, tenantDomain);
            userstore = realm.getUserStoreManager();
            if (userstore.isExistingUser(userName)) {
                String[] newRoles = userstore.getRoleListOfUser(userName);
                StringBuilder sb = new StringBuilder();
                for (String role : newRoles) {
                    sb.append(",").append(role);
                }
                if (sb.length() > 0) {
                    return sb.substring(1); //remove the first comma
                }

            }
        } catch (CarbonException e) {
            LOG.error("Error when getting realm for " + userName + "@" + tenantDomain, e);
        } catch (UserStoreException e) {
            LOG.error("Error when getting user store for " + userName + "@" + tenantDomain, e);
        }
        return StringUtils.EMPTY;
    }
}
