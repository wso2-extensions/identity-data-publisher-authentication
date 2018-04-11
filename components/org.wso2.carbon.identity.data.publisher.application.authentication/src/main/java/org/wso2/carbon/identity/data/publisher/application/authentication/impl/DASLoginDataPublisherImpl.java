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
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.databridge.commons.Event;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthPublisherConstants;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthnDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.application.authentication.internal.AuthenticationDataPublisherDataHolder;
import org.wso2.carbon.identity.data.publisher.application.authentication.model.AuthenticationData;
import org.wso2.carbon.identity.event.IdentityEventConstants.EventName;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.List;
import java.util.UUID;

public class DASLoginDataPublisherImpl extends AbstractEventHandler {

    private static final Log LOG = LogFactory.getLog(DASLoginDataPublisherImpl.class);

    @Override
    public String getName() {

        return AuthPublisherConstants.DAS_LOGIN_PUBLISHER_NAME;
    }

    @Override
    public void handleEvent(org.wso2.carbon.identity.event.event.Event event) throws IdentityEventException {

        if (event.getEventName().equals(EventName.AUTHENTICATION_STEP_SUCCESS.name()) ||
                event.getEventName().equals(EventName.AUTHENTICATION_STEP_FAILURE.name())) {
            AuthenticationData authenticationData = HandlerDataBuilder.buildAuthnDataForAuthnStep(event);
            publishAuthenticationData(authenticationData);
        } else if (event.getEventName().equals(EventName.AUTHENTICATION_SUCCESS.name()) ||
                event.getEventName().equals(EventName.AUTHENTICATION_FAILURE.name())) {
            AuthenticationData authenticationData = HandlerDataBuilder.buildAuthnDataForAuthentication(event);
            publishAuthenticationData(authenticationData);
        } else {
            LOG.error("Event " + event.getEventName() + " cannot be handled");
        }

    }

    protected void publishAuthenticationData(AuthenticationData authenticationData) {

        try {
            String roleList = null;
            if (FrameworkConstants.LOCAL_IDP_NAME.equalsIgnoreCase(authenticationData.getIdentityProviderType())) {
                roleList = getCommaSeparatedUserRoles(authenticationData.getUserStoreDomain() + "/" + authenticationData
                        .getUsername(), authenticationData.getTenantDomain());
            } else if (StringUtils.isNotEmpty(authenticationData.getLocalUsername())) {
                roleList = getCommaSeparatedUserRoles(authenticationData.getUserStoreDomain() + "/" + authenticationData
                        .getLocalUsername(), authenticationData.getTenantDomain());
            }

            Object[] payloadData = new Object[23];
            payloadData[0] = authenticationData.getContextId();
            payloadData[1] = authenticationData.getEventId();
            payloadData[2] = authenticationData.getEventType();
            payloadData[3] = authenticationData.isAuthnSuccess();
            payloadData[4] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                    AuthPublisherConstants.USERNAME, authenticationData.getUsername());
            payloadData[5] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                    AuthPublisherConstants.USERNAME, authenticationData.getLocalUsername());
            payloadData[6] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                    AuthPublisherConstants.USER_STORE_DOMAIN, authenticationData.getUserStoreDomain());
            payloadData[7] = authenticationData.getTenantDomain();
            payloadData[8] = authenticationData.getRemoteIp();
            payloadData[9] = AuthPublisherConstants.NOT_AVAILABLE;
            payloadData[10] = authenticationData.getInboundProtocol();
            payloadData[11] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                    AuthPublisherConstants.SERVICE_PROVIDER, authenticationData
                    .getServiceProvider());
            payloadData[12] = authenticationData.isRememberMe();
            payloadData[13] = authenticationData.isForcedAuthn();
            payloadData[14] = authenticationData.isPassive();
            payloadData[15] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                    AuthPublisherConstants.ROLES, roleList);
            payloadData[16] = String.valueOf(authenticationData.getStepNo());
            payloadData[17] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                    AuthPublisherConstants.IDENTITY_PROVIDER, authenticationData.getIdentityProvider());
            payloadData[18] = authenticationData.isSuccess();
            payloadData[19] = authenticationData.getAuthenticator();
            payloadData[20] = authenticationData.isInitialLogin();
            payloadData[21] = authenticationData.getIdentityProviderType();
            payloadData[22] = System.currentTimeMillis();

            if (LOG.isDebugEnabled()) {
                for (int i = 0; i < 23; i++) {
                    if (payloadData[i] != null) {
                        LOG.debug("Payload data for entry " + i + " " + payloadData[i].toString());
                    } else {
                        LOG.debug("Payload data for entry " + i + " is null");
                    }

                }
            }
            String[] publishingDomains = (String[]) authenticationData.getParameter(AuthPublisherConstants.TENANT_ID);
            if (publishingDomains != null && publishingDomains.length > 0) {

                try {
                    FrameworkUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                    for (String publishingDomain : publishingDomains) {
                        Object[] metadataArray = AuthnDataPublisherUtils.getMetaDataArray(publishingDomain);

                        Event event = new Event(AuthPublisherConstants.AUTHN_DATA_STREAM_NAME, System.currentTimeMillis(),
                                metadataArray, null, payloadData);
                        AuthenticationDataPublisherDataHolder.getInstance().getPublisherService().publish(event);
                        if (LOG.isDebugEnabled() && event != null) {
                            LOG.debug("Sending out event : " + event.toString());
                        }
                        payloadData[1] = UUID.randomUUID().toString();

                    }
                } finally {
                    FrameworkUtils.endTenantFlow();
                }
            }
        } catch (IdentityRuntimeException e) {
            if (LOG.isDebugEnabled()) {
                LOG.error("Error while publishing authentication data", e);
            }
        }

    }

    private String getCommaSeparatedUserRoles(String userName, String tenantDomain) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Retrieving roles for user " + userName + ", tenant domain " + tenantDomain);
        }
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
            if (realm != null) {
                userstore = realm.getUserStoreManager();
                if (userstore.isExistingUser(userName)) {
                    String[] newRoles = userstore.getRoleListOfUser(userName);
                    StringBuilder sb = new StringBuilder();
                    List<String> externalRoles = AuthnDataPublisherUtils.filterRoles(newRoles);
                    for (String role : externalRoles) {
                        sb.append(",").append(role);
                    }
                    if (sb.length() > 0) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Returning roles, " + sb.substring(1));
                        }
                        return sb.substring(1); //remove the first comma
                    }

                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No realm found. for tenant domain : " + tenantDomain + ". Hence no roles added");
                }
            }
        } catch (CarbonException e) {
            LOG.error("Error when getting realm for " + userName + "@" + tenantDomain, e);
        } catch (UserStoreException e) {
            LOG.error("Error when getting user store for " + userName + "@" + tenantDomain, e);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("No roles found. Returning empty string");
        }
        return StringUtils.EMPTY;
    }
}
