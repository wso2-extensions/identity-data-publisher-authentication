/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.data.publisher.authentication.analytics.login;

import org.apache.commons.lang.ArrayUtils;
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

import java.util.*;

/**
 * Publish authentication login data to analytics server.
 */
public class AnalyticsLoginDataPublishHandler extends AbstractEventHandler {

    private static final Log LOG = LogFactory.getLog(AnalyticsLoginDataPublishHandler.class);

    @Override
    public String getName() {

        return AnalyticsLoginDataPublishConstants.ANALYTICS_LOGIN_PUBLISHER_NAME;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        boolean isEnabled = isAnalyticsLoginDataPublishingEnabled(event);

        if (!isEnabled) {
            return;
        }

        if (IdentityEventConstants.EventName.AUTHENTICATION_STEP_SUCCESS.name().equals(event.getEventName()) ||
                IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name().equals(event.getEventName())) {
            AuthenticationData authenticationData = AnalyticsLoginDataPublisherUtils.buildAuthnDataForAuthnStep(event);
            publishAuthenticationData(authenticationData);
        } else if (IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name().equals(event.getEventName()) ||
                IdentityEventConstants.EventName.AUTHENTICATION_FAILURE.name().equals(event.getEventName())) {
            AuthenticationData authenticationData = AnalyticsLoginDataPublisherUtils.
                    buildAuthnDataForAuthentication(event);
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

        Object[] payloadData = new Object[23];
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
        payloadData[22] = System.currentTimeMillis();

        if (LOG.isDebugEnabled()) {
            LOG.debug("The created payload: " + Arrays.asList(payloadData));
        }

        return payloadData;
    }

    protected void publishEvent(Object[] payloadData, AuthenticationData authenticationData) {

        String[] publishingDomains = (String[]) authenticationData
                .getParameter(AnalyticsLoginDataPublishConstants.TENANT_DOMAIN_NAMES);
        if (publishingDomains != null && publishingDomains.length > 0) {
            publishingDomains = processPublishingDomains(publishingDomains, authenticationData.getTenantDomain());

            try {
                FrameworkUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                for (String publishingDomain : publishingDomains) {
                    Object[] metadataArray = AuthnDataPublisherUtils.getMetaDataArray(publishingDomain);
                    payloadData[7] = publishingDomain;
                    payloadData[1] = UUID.randomUUID().toString();

                    org.wso2.carbon.databridge.commons.Event event = new org.wso2.carbon.databridge.commons
                            .Event(AnalyticsLoginDataPublishConstants.AUTHN_DATA_STREAM_NAME,
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
                    .getProperty(AnalyticsLoginDataPublishConstants.ANALYTICS_LOGIN_DATA_PUBLISHER_ENABLED);
            return Boolean.parseBoolean(handlerEnabled);
        }

        return false;
    }

    private boolean isMultipleEventPublishingForSaasAppsEnabled() {

        if (this.configs.getModuleProperties() != null) {
            String multipleEventPublishingForSaasAppsEnabled = this.configs.getModuleProperties().
                    getProperty(AnalyticsLoginDataPublishConstants.
                            ANALYTICS_LOGIN_DATA_PUBLISHER_ENABLE_MULTIPLE_EVENT_PUBLISHING_FOR_SAAS_APPS);
            if (StringUtils.isNotBlank(multipleEventPublishingForSaasAppsEnabled)) {
                return Boolean.parseBoolean(multipleEventPublishingForSaasAppsEnabled);
            }
        }
        // If Multiple Event Publishing For SaaS Apps property is not defined, return true as default value.
        return true;
    }

    /**
     * Process publishing tenant domains according to config `enableMultipleEventPublishingForSaasApps`.
     * If multiple event publishing disabled for the SaaS apps, return only SP tenant domain as publishing domain.
     *
     * @param publishingDomains Publishing tenant domains array.
     * @param userTenantDomain  User tenant domain.
     * @return Processed publishing tenant domains.
     */
    private String[] processPublishingDomains(String[] publishingDomains, String userTenantDomain) {

        if (!isMultipleEventPublishingForSaasAppsEnabled() && ArrayUtils.getLength(publishingDomains) == 2 &&
                StringUtils.isNotBlank(userTenantDomain)) {
            // If we have two publishing domains one is user tenant domain and other one is sp tenant domain.
            String spTenantDomain;
            if (userTenantDomain.equalsIgnoreCase(publishingDomains[0])) {
                spTenantDomain = publishingDomains[1];
            } else {
                spTenantDomain = publishingDomains[0];
            }
            // If multiple event publishing disabled for the SaaS apps, publishing events only for the SP tenant domain.
            return new String[]{spTenantDomain};
        }
        return publishingDomains;
    }
}
