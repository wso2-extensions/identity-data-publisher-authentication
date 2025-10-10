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

package org.wso2.carbon.identity.data.publisher.authentication.analytics.login;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthPublisherConstants;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthnDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.login.internal.AnalyticsLoginDataPublishDataHolder;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.login.model.B2BAuthenticationData;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;

import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.UNFILTERED_IDP_CLAIM_VALUES;

/**
 * Publish B2B authentication login data to analytics server.
 */
public class AnalyticsB2BLoginDataPublishHandler extends AbstractEventHandler  {

    private static final Log LOG = LogFactory.getLog(AnalyticsB2BLoginDataPublishHandler.class);

    private static final String USERNAME_CLAIM = "username";
    private static final String ORG_NAME_CLAIM = "org_name";
    private static final String SUB_CLAIM = "sub";
    private static final String IS_FRAGMENT_APP = "isFragmentApp";

    @Override
    public String getName() {

        return AnalyticsLoginDataPublishConstants.ANALYTICS_B2B_LOGIN_PUBLISHER_NAME;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        boolean isEnabled = isAnalyticsB2BLoginDataPublishingEnabled();

        if (!isEnabled) {
            return;
        }

        if (IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name().equals(event.getEventName())) {
            Map<String, Object> properties = event.getEventProperties();
            AuthenticationContext context = (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.
                    CONTEXT);
            boolean isInternalFederation = isInternalSubOrganizationLogin(context);
            if (isInternalFederation) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Skipping event " + event.getEventName() + " in " + getName() +
                            " since it is an internal sub-organization login.");
                }
                return;
            }
            String spTenantDomain = context.getTenantDomain();
            B2BAuthenticationData authenticationData = buildAuthnDataForAuthentication(event);
            publishAuthenticationData(authenticationData, spTenantDomain);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Event " + event.getEventName() + " cannot be handled in " + getName() + ".");
            }
        }
    }

    private B2BAuthenticationData buildAuthnDataForAuthentication(Event event) {

        Map<String, Object> properties = event.getEventProperties();
        HttpServletRequest request = (HttpServletRequest) properties.get(IdentityEventConstants.EventProperty.REQUEST);
        Map<String, Object> params = (Map<String, Object>) properties.get(IdentityEventConstants.EventProperty.PARAMS);
        AuthenticationContext context = (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.
                CONTEXT);

        B2BAuthenticationData authenticationData = new B2BAuthenticationData();
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        setUserDataForAuthentication(authenticationData, userObj, context);

        authenticationData.setEventType(AnalyticsLoginDataPublishConstants.OVERALL_EVENT);
        authenticationData.setContextId(context.getContextIdentifier());
        authenticationData.setEventId(UUID.randomUUID().toString());
        if (request != null) {
            authenticationData.setRemoteIp(IdentityUtil.getClientIpAddress(request));
        } else {
            authenticationData.setRemoteIp((String) params.get(AuthPublisherConstants.REMOTE_IP_ADDRESS));
        }
        authenticationData.setServiceProvider(context.getServiceProviderName());
        authenticationData.setInboundProtocol(context.getRequestType());

        return authenticationData;
    }

    private void setUserDataForAuthentication(B2BAuthenticationData authenticationData,
                                                     Object userObj, AuthenticationContext context) {

        if (userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            if (user.getAccessingOrganization() != null) {
                authenticationData.setOrganizationLogin(true);
                Map<String, String> remoteClaims =
                        (Map<String, String>) context.getProperty(UNFILTERED_IDP_CLAIM_VALUES);
                authenticationData.setUsername(remoteClaims.get(USERNAME_CLAIM));
                authenticationData.setOrganizationName(remoteClaims.get(ORG_NAME_CLAIM));
                authenticationData.setUserId(remoteClaims.get(SUB_CLAIM));
            } else {
                authenticationData.setUsername(user.getUserName());
                try {
                    authenticationData.setUserId(user.getUserId());
                } catch (UserIdNotFoundException e) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Null user id is found in the AuthenticatedUser instance.");
                    }
                }
            }
            authenticationData.setTenantDomain(user.getTenantDomain());
        }
    }



    private void publishAuthenticationData(B2BAuthenticationData authenticationData, String spTenantDomain) {

        try {
            Object[] payloadData = populatePayloadData(authenticationData);
            publishEvent(payloadData, spTenantDomain);
        } catch (IdentityRuntimeException e) {
            LOG.error("Error while publishing authentication data", e);
        }
    }

    private Object[] populatePayloadData(B2BAuthenticationData authenticationData) {

        Object[] payloadData = new Object[11];
        payloadData[0] = authenticationData.getContextId();
        payloadData[1] = authenticationData.getEventId();
        payloadData[2] = authenticationData.getEventType();
        payloadData[3] = AuthnDataPublisherUtils.replaceIfNotAvailable(
                AuthPublisherConstants.CONFIG_PREFIX + AuthPublisherConstants.USERNAME,
                authenticationData.getUsername());
        payloadData[4] = authenticationData.getTenantDomain();
        payloadData[5] = authenticationData.getRemoteIp();
        payloadData[6] = AuthPublisherConstants.NOT_AVAILABLE;
        payloadData[7] = authenticationData.getInboundProtocol();
        payloadData[8] = AuthnDataPublisherUtils.replaceIfNotAvailable(
                AuthPublisherConstants.CONFIG_PREFIX + AuthPublisherConstants.SERVICE_PROVIDER,
                authenticationData.getServiceProvider());
        payloadData[9] = authenticationData.isOrganizationLogin();
        payloadData[10] = authenticationData.getOrganizationName() != null ?
                authenticationData.getOrganizationName() : AuthPublisherConstants.NOT_AVAILABLE;

        return payloadData;
    }

    private void publishEvent(Object[] payloadData, String spTenantDomain) {

        try {
            FrameworkUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
            Object[] metadataArray = AuthnDataPublisherUtils.getMetaDataArray(spTenantDomain);
            payloadData[4] = spTenantDomain;

            org.wso2.carbon.databridge.commons.Event event = new org.wso2.carbon.databridge.commons
                    .Event(AnalyticsLoginDataPublishConstants.B2B_AUTHN_DATA_STREAM_NAME,
                    System.currentTimeMillis(), metadataArray, null, payloadData);
            AnalyticsLoginDataPublishDataHolder.getInstance().getPublisherService().publish(event);
        } finally {
            FrameworkUtils.endTenantFlow();
        }
    }

    private boolean isAnalyticsB2BLoginDataPublishingEnabled() {

        if (this.configs.getModuleProperties() != null) {
            String handlerEnabled = this.configs.getModuleProperties()
                    .getProperty(AnalyticsLoginDataPublishConstants.ANALYTICS_B2B_LOGIN_DATA_PUBLISHER_ENABLED);
            return Boolean.parseBoolean(handlerEnabled);
        }
        return false;
    }

    private static boolean isInternalSubOrganizationLogin(AuthenticationContext context) {

        SequenceConfig sequenceConfig = context.getSequenceConfig();
        ServiceProvider serviceProvider =  sequenceConfig.getApplicationConfig().getServiceProvider();
        if (serviceProvider != null) {
            ServiceProviderProperty[] spProperties = serviceProvider.getSpProperties();
            if (spProperties != null) {
                for (ServiceProviderProperty spProperty : spProperties) {
                    if (StringUtils.equals(spProperty.getName(), IS_FRAGMENT_APP)
                            && StringUtils.equals(spProperty.getValue(), Boolean.TRUE.toString())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
