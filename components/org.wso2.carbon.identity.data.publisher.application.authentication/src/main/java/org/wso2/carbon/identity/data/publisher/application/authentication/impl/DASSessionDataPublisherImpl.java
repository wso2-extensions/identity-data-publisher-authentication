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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthPublisherConstants;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthnDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.application.authentication.internal.AuthenticationDataPublisherDataHolder;
import org.wso2.carbon.identity.data.publisher.application.authentication.model.SessionData;
import org.wso2.carbon.identity.event.IdentityEventConstants.EventName;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

public class DASSessionDataPublisherImpl extends AbstractEventHandler {

    private static final Log LOG = LogFactory.getLog(DASSessionDataPublisherImpl.class);

    @Override
    public String getName() {
        return AuthPublisherConstants.DAS_SESSION_PUBLISHER_NAME;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        SessionData sessionData = HandlerDataBuilder.buildSessionData(event);
        if (event.getEventName().equals(EventName.SESSION_CREATE.name())) {
            doPublishSessionCreation(sessionData);
        } else if (event.getEventName().equals(EventName.SESSION_TERMINATE.name())) {
            doPublishSessionTermination(sessionData);
        } else if (event.getEventName().equals(EventName.SESSION_UPDATE.name())) {
            doPublishSessionUpdate(sessionData);
        }else {
            LOG.error("Event "+event.getEventName() +" cannot be handled");
        }
    }

    private void doPublishSessionCreation(SessionData sessionData) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Publishing session creation to DAS");
        }
        publishSessionData(sessionData, AuthPublisherConstants.SESSION_CREATION_STATUS);
    }

    private void doPublishSessionTermination(SessionData sessionData) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Publishing session termination to DAS");
        }
        publishSessionData(sessionData, AuthPublisherConstants.SESSION_TERMINATION_STATUS);

    }

    private void doPublishSessionUpdate(SessionData sessionData) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Publishing session update to DAS");
        }
        publishSessionData(sessionData, AuthPublisherConstants.SESSION_UPDATE_STATUS);
    }

    private void publishSessionData(SessionData sessionData, int actionId) {

        if (sessionData != null) {
            Object[] payloadData = new Object[15];
            try {
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
                    for (int i = 0; i < 14; i++) {
                        if (payloadData[i] != null) {
                            LOG.debug("Payload data for entry " + i + " " + payloadData[i].toString());
                        } else {
                            LOG.debug("Payload data for entry " + i + " is null");
                        }
                    }
                }

                String[] publishingDomains = (String[]) sessionData.getParameter(AuthPublisherConstants.TENANT_ID);
                if (publishingDomains != null && publishingDomains.length > 0) {
                    try {
                        FrameworkUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                        for (String publishingDomain : publishingDomains) {
                            Object[] metadataArray = AuthnDataPublisherUtils.getMetaDataArray(publishingDomain);
                            org.wso2.carbon.databridge.commons.Event event =
                                    new org.wso2.carbon.databridge.commons.Event(AuthPublisherConstants.SESSION_DATA_STREAM_NAME, System
                                            .currentTimeMillis(), metadataArray, null, payloadData);
                            AuthenticationDataPublisherDataHolder.getInstance().getPublisherService().publish(event);
                            if (LOG.isDebugEnabled() && event != null) {
                                LOG.debug("Sending out event : " + event.toString());
                            }
                        }
                    } finally {
                        FrameworkUtils.endTenantFlow();
                    }
                }

            } catch (IdentityRuntimeException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.error("Error while publishing session information", e);
                }
            }
        }
    }
}
