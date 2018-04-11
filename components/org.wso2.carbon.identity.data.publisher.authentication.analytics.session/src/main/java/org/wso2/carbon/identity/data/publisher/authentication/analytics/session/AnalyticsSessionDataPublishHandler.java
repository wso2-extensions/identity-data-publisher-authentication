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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.session.internal.SessionDataPublishServiceHolder;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.session.model.SessionData;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

/*
 * Handle data publishing for analytics
 */
public class AnalyticsSessionDataPublishHandler extends AbstractEventHandler {

    private static final Log LOG = LogFactory.getLog(AnalyticsSessionDataPublishHandler.class);

    @Override
    public String getName() {

        return SessionDataPublisherConstants.ANALYTICS_SESSION_PUBLISHER_NAME;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        SessionData sessionData = SessionDataPublisherUtil.buildSessionData(event);
        if (event.getEventName().equals(IdentityEventConstants.EventName.SESSION_CREATE.name())) {
            doPublishSessionCreation(sessionData);
        } else if (event.getEventName().equals(IdentityEventConstants.EventName.SESSION_TERMINATE.name())) {
            doPublishSessionTermination(sessionData);
        } else if (event.getEventName().equals(IdentityEventConstants.EventName.SESSION_UPDATE.name())) {
            doPublishSessionUpdate(sessionData);
        } else {
            LOG.error("Event " + event.getEventName() + " cannot be handled");
        }
    }

    protected void doPublishSessionCreation(SessionData sessionData) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Publishing session creation to DAS");
        }
        publishSessionData(sessionData, SessionDataPublisherConstants.SESSION_CREATION_STATUS);
    }

    protected void doPublishSessionTermination(SessionData sessionData) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Publishing session termination to DAS");
        }
        publishSessionData(sessionData, SessionDataPublisherConstants.SESSION_TERMINATION_STATUS);

    }

    protected void doPublishSessionUpdate(SessionData sessionData) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Publishing session update to DAS");
        }
        publishSessionData(sessionData, SessionDataPublisherConstants.SESSION_UPDATE_STATUS);
    }

    protected void publishSessionData(SessionData sessionData, int actionId) {
        SessionDataPublisherUtil.updateTimeStamps(sessionData,actionId);
        if (sessionData != null) {
            try {
                Object[] payloadData = createPayload(sessionData, actionId);
                publishToAnalytics(sessionData, payloadData);

            } catch (IdentityRuntimeException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.error("Error while publishing session information", e);
                }
            }
        }
    }

    protected void publishToAnalytics(SessionData sessionData, Object[] payloadData) {

        String[] publishingDomains = (String[]) sessionData.getParameter(SessionDataPublisherConstants.TENANT_ID);
        if (publishingDomains != null && publishingDomains.length > 0) {
            try {
                FrameworkUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                for (String publishingDomain : publishingDomains) {
                    Object[] metadataArray = SessionDataPublisherUtil.getMetaDataArray(publishingDomain);
                    org.wso2.carbon.databridge.commons.Event event =
                            new org.wso2.carbon.databridge.commons.Event(SessionDataPublisherConstants.SESSION_DATA_STREAM_NAME, System
                                    .currentTimeMillis(), metadataArray, null, payloadData);
                            SessionDataPublishServiceHolder.getInstance().getPublisherService().publish(event);
                    if (LOG.isDebugEnabled() && event != null) {
                        LOG.debug("Sending out event : " + event.toString());
                    }
                }
            } finally {
                FrameworkUtils.endTenantFlow();
            }
        }
    }

    protected Object[] createPayload(SessionData sessionData, int actionId) {

        Object[] payloadData = new Object[15];
        payloadData[0] = SessionDataPublisherUtil.replaceIfNotAvailable(SessionDataPublisherConstants.CONFIG_PREFIX +
                SessionDataPublisherConstants.SESSION_ID, sessionData.getSessionId());
        payloadData[1] = sessionData.getCreatedTimestamp();
        payloadData[2] = sessionData.getUpdatedTimestamp();
        payloadData[3] = sessionData.getTerminationTimestamp();
        payloadData[4] = actionId;
        payloadData[5] = SessionDataPublisherUtil.replaceIfNotAvailable(SessionDataPublisherConstants.CONFIG_PREFIX +
                SessionDataPublisherConstants.USERNAME, sessionData.getUser());
        payloadData[6] = SessionDataPublisherUtil.replaceIfNotAvailable(SessionDataPublisherConstants.CONFIG_PREFIX +
                SessionDataPublisherConstants.USER_STORE_DOMAIN, sessionData.getUserStoreDomain());
        payloadData[7] = sessionData.getRemoteIP();
        payloadData[8] = SessionDataPublisherConstants.NOT_AVAILABLE;
        payloadData[9] = sessionData.getTenantDomain();
        payloadData[10] = sessionData.getServiceProvider();
        payloadData[11] = sessionData.getIdentityProviders();
        payloadData[12] = sessionData.isRememberMe();
        payloadData[13] = sessionData.getUserAgent();
        payloadData[14] = System.currentTimeMillis();

        if (LOG.isDebugEnabled()) {
            for (int i = 0; i < 14; i++) {
                if (payloadData[i] != null) {
                    LOG.debug("Payload data for entry " + i + " " + payloadData[i].toString());
                } else {
                    LOG.debug("Payload data for entry " + i + " is null");
                }
            }
        }
        return payloadData;
    }

}
