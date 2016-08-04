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
import org.wso2.carbon.databridge.commons.Event;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.data.publisher.application.authentication.AbstractAuthenticationDataPublisher;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthPublisherConstants;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthnDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.application.authentication.internal.AuthenticationDataPublisherDataHolder;
import org.wso2.carbon.identity.data.publisher.application.authentication.model.AuthenticationData;
import org.wso2.carbon.identity.data.publisher.application.authentication.model.SessionData;

import javax.servlet.http.HttpServletRequest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public class DASSessionDataPublisherImpl extends AbstractAuthenticationDataPublisher {

    public static final Log LOG = LogFactory.getLog(DASSessionDataPublisherImpl.class);

    @Override
    public void publishAuthenticationStepSuccess(HttpServletRequest request, AuthenticationContext context,
                                                 Map<String, Object> params) {
        // This method is overridden to do nothing since this is a session data publisher.
    }

    @Override
    public void publishAuthenticationStepFailure(HttpServletRequest request, AuthenticationContext context,
                                                 Map<String, Object> params) {
        // This method is overridden to do nothing since this is a session data publisher.
    }

    @Override
    public void publishAuthenticationSuccess(HttpServletRequest request, AuthenticationContext context, Map<String,
            Object> params) {
        // This method is overridden to do nothing since this is a session data publisher.
    }

    @Override
    public void publishAuthenticationFailure(HttpServletRequest request, AuthenticationContext context, Map<String,
            Object> params) {
        // This method is overridden to do nothing since this is a session data publisher.
    }

    @Override
    public void doPublishAuthenticationStepSuccess(AuthenticationData authenticationData) {
        // This method is not implemented since there is no usage of it in session publishing
    }

    @Override
    public void doPublishAuthenticationStepFailure(AuthenticationData authenticationData) {
        // This method is not implemented since there is no usage of it in session publishing
    }

    @Override
    public void doPublishAuthenticationSuccess(AuthenticationData authenticationData) {
        // This method is not implemented since there is no usage of it in session publishing
    }

    @Override
    public void doPublishAuthenticationFailure(AuthenticationData authenticationData) {
        // This method is not implemented since there is no usage of it in session publishing
    }

    @Override
    public void doPublishSessionCreation(SessionData sessionData) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Publishing session creation to DAS");
        }
        publishSessionData(sessionData, AuthPublisherConstants.SESSION_CREATION_STATUS);
    }

    @Override
    public void doPublishSessionTermination(SessionData sessionData) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Publishing session termination to DAS");
        }
        publishSessionData(sessionData, AuthPublisherConstants.SESSION_TERMINATION_STATUS);

    }

    @Override
    public void doPublishSessionUpdate(SessionData sessionData) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Publishing session update to DAS");
        }
        publishSessionData(sessionData, AuthPublisherConstants.SESSION_UPDATE_STATUS);
    }

    @Override
    public String getName() {
        return AuthPublisherConstants.DAS_SESSION_PUBLISHER_NAME;
    }

    protected void publishSessionData(SessionData sessionData, int actionId) {

        if (sessionData != null) {
            Object[] payloadData = new Object[15];
            try {
                payloadData[0] = AuthnDataPublisherUtils.replaceIfNotAvailable(AuthPublisherConstants.CONFIG_PREFIX +
                        AuthPublisherConstants.SESSION_ID, AuthnDataPublisherUtils.hashString(sessionData.getSessionId()));
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
                    for (String publishingDomain : publishingDomains) {
                        Object[] metadataArray = AuthnDataPublisherUtils.getMetaDataArray(publishingDomain);
                        Event event = new Event(AuthPublisherConstants.SESSION_DATA_STREAM_NAME, System
                                .currentTimeMillis(), metadataArray, null, payloadData);
                        AuthenticationDataPublisherDataHolder.getInstance().getPublisherService().publish(event);
                    }
                }

            } catch (NoSuchAlgorithmException e) {
                LOG.error("Error while hashing session id.", e);
            } catch (IdentityRuntimeException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.error("Error while publishing session information", e);
                }
            }
        }
    }
}
