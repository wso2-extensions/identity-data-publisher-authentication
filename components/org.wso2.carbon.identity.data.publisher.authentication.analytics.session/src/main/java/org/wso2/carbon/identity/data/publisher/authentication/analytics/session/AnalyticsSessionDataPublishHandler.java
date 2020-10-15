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

package org.wso2.carbon.identity.data.publisher.authentication.analytics.session;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthPublisherConstants;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthnDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.session.internal.SessionDataPublishServiceHolder;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.session.model.SessionData;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.Arrays;

/**
 * Handle data publishing for analytics.
 */
public class AnalyticsSessionDataPublishHandler extends AbstractEventHandler {

    private static final Log LOG = LogFactory.getLog(AnalyticsSessionDataPublishHandler.class);

    @Override
    public String getName() {

        return SessionDataPublisherConstants.ANALYTICS_SESSION_PUBLISHER_NAME;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        boolean isEnabled = isAnalyticsSessionDataPublishingEnabled(event);

        if (!isEnabled) {
            return;
        }

        SessionData sessionData = SessionDataPublisherUtil.buildSessionData(event);
        if (IdentityEventConstants.EventName.SESSION_CREATE.name().equals(event.getEventName())) {
            doPublishSessionCreation(sessionData);
        } else if (IdentityEventConstants.EventName.SESSION_TERMINATE.name().equals(event.getEventName())) {
            doPublishSessionTermination(sessionData);
        } else if (IdentityEventConstants.EventName.SESSION_UPDATE.name().equals(event.getEventName())) {
            doPublishSessionUpdate(sessionData);
        } else {
            LOG.error("Event " + event.getEventName() + " cannot be handled");
        }
    }

    protected void doPublishSessionCreation(SessionData sessionData) {

        publishSessionData(sessionData, SessionDataPublisherConstants.SESSION_CREATION_STATUS);
    }

    protected void doPublishSessionTermination(SessionData sessionData) {

        publishSessionData(sessionData, SessionDataPublisherConstants.SESSION_TERMINATION_STATUS);

    }

    protected void doPublishSessionUpdate(SessionData sessionData) {

        publishSessionData(sessionData, SessionDataPublisherConstants.SESSION_UPDATE_STATUS);
    }

    protected void publishSessionData(SessionData sessionData, int actionId) {

        SessionDataPublisherUtil.updateTimeStamps(sessionData, actionId);
        try {
            Object[] payloadData;
            if (isPublishingSessionCountEnabled()) {
                payloadData = createPayloadWithSessionCount(sessionData, actionId);
                publishToAnalytics(sessionData, payloadData, AuthPublisherConstants
                        .SESSION_DATA_STREAM_WITH_SESSION_COUNT_NAME);
            } else {
                payloadData = createPayload(sessionData, actionId);
                publishToAnalytics(sessionData, payloadData, AuthPublisherConstants.SESSION_DATA_STREAM_NAME);
            }

        } catch (IdentityRuntimeException e) {
            if (LOG.isDebugEnabled()) {
                LOG.error("Error while publishing session information", e);
            }
        }

    }

    private void publishToAnalytics(SessionData sessionData, Object[] payloadData, String eventStreamName) {

        String[] publishingDomains = (String[]) sessionData.getParameter(AuthPublisherConstants.TENANT_ID);
        if (publishingDomains != null && publishingDomains.length > 0) {
            try {
                FrameworkUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                for (String publishingDomain : publishingDomains) {
                    Object[] metadataArray = AuthnDataPublisherUtils.getMetaDataArray(publishingDomain);
                    org.wso2.carbon.databridge.commons.Event event =
                            new org.wso2.carbon.databridge.commons.Event(eventStreamName, System.currentTimeMillis(),
                                    metadataArray, null, payloadData);
                    SessionDataPublishServiceHolder.getInstance().getPublisherService().publish(event);
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

    private Object[] createPayload(SessionData sessionData, int actionId) {

        Object[] payloadData = new Object[15];
        payloadData[0] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                AuthPublisherConstants.SESSION_ID, sessionData.getSessionId());
        payloadData[1] = sessionData.getCreatedTimestamp();
        payloadData[2] = sessionData.getUpdatedTimestamp();
        payloadData[3] = sessionData.getTerminationTimestamp();
        payloadData[4] = actionId;
        payloadData[5] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                AuthPublisherConstants.USERNAME, sessionData.getUser());
        payloadData[6] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                AuthPublisherConstants.USER_STORE_DOMAIN, sessionData.getUserStoreDomain());
        payloadData[7] = sessionData.getRemoteIP();
        payloadData[8] = AuthPublisherConstants.NOT_AVAILABLE;
        payloadData[9] = sessionData.getTenantDomain();
        payloadData[10] = sessionData.getServiceProvider();
        payloadData[11] = sessionData.getIdentityProviders();
        payloadData[12] = sessionData.isRememberMe();
        payloadData[13] = sessionData.getUserAgent();
        payloadData[14] = System.currentTimeMillis();

        if (LOG.isDebugEnabled()) {
            LOG.debug("The created payload :" + Arrays.asList(payloadData));
        }
        return payloadData;
    }

    private Object[] createPayloadWithSessionCount(SessionData sessionData, int actionId) {

        Object[] payloadData = new Object[16];
        payloadData[0] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                AuthPublisherConstants.SESSION_ID, sessionData.getSessionId());
        payloadData[1] = sessionData.getCreatedTimestamp();
        payloadData[2] = sessionData.getUpdatedTimestamp();
        payloadData[3] = sessionData.getTerminationTimestamp();
        payloadData[4] = actionId;
        payloadData[5] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                AuthPublisherConstants.USERNAME, sessionData.getUser());
        payloadData[6] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                AuthPublisherConstants.USER_STORE_DOMAIN, sessionData.getUserStoreDomain());
        payloadData[7] = sessionData.getRemoteIP();
        payloadData[8] = AuthPublisherConstants.NOT_AVAILABLE;
        payloadData[9] = sessionData.getTenantDomain();
        payloadData[10] = sessionData.getServiceProvider();
        payloadData[11] = sessionData.getIdentityProviders();
        payloadData[12] = sessionData.isRememberMe();
        payloadData[13] = sessionData.getUserAgent();
        payloadData[14] = sessionData.getActiveSessionCount();
        payloadData[15] = System.currentTimeMillis();
        if (LOG.isDebugEnabled()) {
            LOG.debug("The created payload :" + Arrays.asList(payloadData));
        }
        return payloadData;
    }

    @Override
    public boolean isEnabled(MessageContext messageContext) {
        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.readEventListenerProperty
                (AbstractIdentityMessageHandler.class.getName(), this.getClass().getName());

        if (identityEventListenerConfig == null) {
            return false;
        }

        return Boolean.parseBoolean(identityEventListenerConfig.getEnable());
    }

    private boolean isAnalyticsSessionDataPublishingEnabled(Event event) throws IdentityEventException {

        if (this.configs.getModuleProperties() != null) {
            String handlerEnabled = this.configs.getModuleProperties().getProperty(SessionDataPublisherConstants.
                    ANALYTICS_SESSION_DATA_PUBLISHER_ENABLED);
            return Boolean.parseBoolean(handlerEnabled);
        }

        return false;
    }

    private boolean isPublishingSessionCountEnabled() {

        String isPublishingSessionCountEnabledValue = IdentityUtil.getProperty(FrameworkConstants.Config
                .PUBLISH_ACTIVE_SESSION_COUNT);
        return Boolean.parseBoolean(isPublishingSessionCountEnabledValue);
    }
}
