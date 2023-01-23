/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.data.publisher.authentication.analytics.login;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthPublisherConstants;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthnDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.login.internal.AnalyticsLoginDataPublishDataHolder;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.login.model.AuthenticationData;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.List;
import java.util.UUID;

/**
 * Publish authentication login data to analytics server.
 * This is introduced
 */
public class AnalyticsLoginDataPublishHandlerV110 extends AbstractEventHandler {

    private static final Log LOG = LogFactory.getLog(AnalyticsLoginDataPublishHandlerV110.class);
    private static final int PAYLOAD_LENGTH = 31;

    @Override
    public String getName() {

        return AnalyticsLoginDataPublishConstants.ANALYTICS_LOGIN_PUBLISHER_V110_NAME;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        boolean isEnabled = isAnalyticsLoginDataPublishingEnabled(event);

        if (!isEnabled) {
            return;
        }

        if (IdentityEventConstants.EventName.AUTHENTICATION_STEP_SUCCESS.name().equals(event.getEventName()) ||
                IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name().equals(event.getEventName())) {
            AuthenticationData authenticationData =
                    AnalyticsLoginDataPublisherUtils.buildAuthnDataForAuthnStepV110(event);
            publishAuthenticationData(authenticationData);
        } else if (IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name().equals(event.getEventName()) ||
                IdentityEventConstants.EventName.AUTHENTICATION_FAILURE.name().equals(event.getEventName())) {
            AuthenticationData authenticationData = AnalyticsLoginDataPublisherUtils.
                    buildAuthnDataForAuthenticationV110(event);
            publishAuthenticationData(authenticationData);
        } else {
            LOG.error("Event " + event.getEventName() + " cannot be handled");
        }
    }

    protected void publishAuthenticationData(AuthenticationData authenticationData) {

        try {
            Object[] payloadData = populatePayloadData(authenticationData);
            publishEvent(payloadData, authenticationData);
        } catch (IdentityRuntimeException e) {
            if (LOG.isDebugEnabled()) {
                LOG.error("Error while publishing authentication data", e);
            }
        }
    }

    protected Object[] populatePayloadData(AuthenticationData authenticationData) {

        String roleList = null;
        if (FrameworkConstants.LOCAL_IDP_NAME.equalsIgnoreCase(authenticationData.getIdentityProviderType())) {
            roleList = getCommaSeparatedUserRoles(authenticationData.getUserStoreDomain() + "/" +
                    authenticationData.getUsername(), authenticationData.getTenantDomain());
        } else if (StringUtils.isNotEmpty(authenticationData.getLocalUsername())) {
            roleList = getCommaSeparatedUserRoles(authenticationData.getUserStoreDomain() + "/" +
                    authenticationData.getLocalUsername(), authenticationData.getTenantDomain());
        }

        Object[] payloadData = new Object[PAYLOAD_LENGTH];
        payloadData[0] = authenticationData.getContextId();
        payloadData[1] = authenticationData.getEventId();
        payloadData[2] = authenticationData.getEventType();
        payloadData[3] = authenticationData.isAuthnSuccess();
        payloadData[4] = AuthnDataPublisherUtils.replaceIfNotAvailable(
                AuthPublisherConstants.CONFIG_PREFIX + AuthPublisherConstants.USERNAME,
                authenticationData.getUsername());
        payloadData[5] = AuthnDataPublisherUtils.replaceIfNotAvailable(
                AuthPublisherConstants.CONFIG_PREFIX + AuthPublisherConstants.USERNAME,
                authenticationData.getLocalUsername());
        payloadData[6] = AuthnDataPublisherUtils.replaceIfNotAvailable(
                AuthPublisherConstants.CONFIG_PREFIX + AuthPublisherConstants.USER_STORE_DOMAIN,
                authenticationData.getUserStoreDomain());
        payloadData[7] = authenticationData.getTenantDomain();
        payloadData[8] = authenticationData.getRemoteIp();
        payloadData[9] = AuthPublisherConstants.NOT_AVAILABLE;
        payloadData[10] = authenticationData.getInboundProtocol();
        payloadData[11] = AuthnDataPublisherUtils.replaceIfNotAvailable(
                AuthPublisherConstants.CONFIG_PREFIX + AuthPublisherConstants.SERVICE_PROVIDER,
                authenticationData.getServiceProvider());
        payloadData[12] = authenticationData.isRememberMe();
        payloadData[13] = authenticationData.isForcedAuthn();
        payloadData[14] = authenticationData.isPassive();
        payloadData[15] = AuthnDataPublisherUtils.replaceIfNotAvailable(
                AuthPublisherConstants.CONFIG_PREFIX + AuthPublisherConstants.ROLES, roleList);
        payloadData[16] = String.valueOf(authenticationData.getStepNo());
        payloadData[17] = AuthnDataPublisherUtils.replaceIfNotAvailable(
                AuthPublisherConstants.CONFIG_PREFIX + AuthPublisherConstants.IDENTITY_PROVIDER,
                authenticationData.getIdentityProvider());
        payloadData[18] = authenticationData.isSuccess();
        payloadData[19] = authenticationData.getAuthenticator();
        payloadData[20] = authenticationData.isInitialLogin();
        payloadData[21] = authenticationData.getIdentityProviderType();
        payloadData[22] = AuthnDataPublisherUtils.replaceIfNotAvailable(
                AuthPublisherConstants.CONFIG_PREFIX + AuthPublisherConstants.USERNAME_USER_INPUT,
                authenticationData.getUsernameUserInput());
        payloadData[23] = System.currentTimeMillis();
        payloadData[24] = AnalyticsLoginDataPublisherUtils.replaceIfLongNotAvailable(authenticationData.getDuration());
        payloadData[25] =
                AnalyticsLoginDataPublisherUtils.replaceIfStringNotAvailable(authenticationData.getErrorCode());

        List<String> customParams = authenticationData.getCustomParams();
        for (int i = 0; i < customParams.size(); i++) {
            payloadData[26 + i] = customParams.get(i);
        }

        if (LOG.isDebugEnabled()) {
            for (int i = 0; i < PAYLOAD_LENGTH; i++) {
                if (payloadData[i] != null) {
                    LOG.debug("Payload data for entry " + i + " " + payloadData[i].toString());
                } else {
                    LOG.debug("Payload data for entry " + i + " is null");
                }
            }
        }

        return payloadData;
    }

    protected void publishEvent(Object[] payloadData, AuthenticationData authenticationData) {

        String[] publishingDomains = (String[]) authenticationData
                .getParameter(AnalyticsLoginDataPublishConstants.TENANT_DOMAIN_NAMES);
        if (publishingDomains != null && publishingDomains.length > 0) {

            try {
                FrameworkUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                for (String publishingDomain : publishingDomains) {
                    Object[] metadataArray = AuthnDataPublisherUtils.getMetaDataArray(publishingDomain);
                    payloadData[7] = publishingDomain;
                    payloadData[1] = UUID.randomUUID().toString();

                    org.wso2.carbon.databridge.commons.Event event = new org.wso2.carbon.databridge.commons
                            .Event(AnalyticsLoginDataPublishConstants.AUTHN_DATA_STREAM_1_1_0_NAME,
                            System.currentTimeMillis(), metadataArray, null, payloadData);
                    AnalyticsLoginDataPublishDataHolder.getInstance().getPublisherService().publish(event);
                    if (LOG.isDebugEnabled() && event != null) {
                        LOG.debug("Sending out to publishing domain:" + publishingDomain + " \n event : "
                                + event.toString());
                    }
                }
            } finally {
                FrameworkUtils.endTenantFlow();
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

        RegistryService registryService = AnalyticsLoginDataPublishDataHolder.getInstance().getRegistryService();
        RealmService realmService = AnalyticsLoginDataPublishDataHolder.getInstance().getRealmService();

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

    private boolean isAnalyticsLoginDataPublishingEnabled(Event event) throws IdentityEventException {

        if (this.configs.getModuleProperties() != null) {
            String handlerEnabled = this.configs.getModuleProperties()
                    .getProperty(AnalyticsLoginDataPublishConstants.ANALYTICS_LOGIN_DATA_PUBLISHER_V110_ENABLED);
            return Boolean.parseBoolean(handlerEnabled);
        }
        return false;
    }
}
