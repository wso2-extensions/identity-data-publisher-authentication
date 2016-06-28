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
import org.wso2.carbon.databridge.commons.Event;
import org.wso2.carbon.identity.application.authentication.framework.AbstractAuthenticationDataPublisher;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationData;
import org.wso2.carbon.identity.application.authentication.framework.model.SessionData;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthPublisherConstants;
import org.wso2.carbon.identity.data.publisher.application.authentication.internal.AuthenticationDataPublisherDataHolder;

public class DASSessionDataPublisherImpl extends AbstractAuthenticationDataPublisher {

    public static final Log LOG = LogFactory.getLog(DASSessionDataPublisherImpl.class);

    @Override
    public void doPublishAuthenticationStepSuccess(AuthenticationData authenticationData) {
    }

    @Override
    public void doPublishAuthenticationStepFailure(AuthenticationData authenticationData) {
    }

    @Override
    public void doPublishAuthenticationSuccess(AuthenticationData authenticationData) {
    }

    @Override
    public void doPublishAuthenticationFailure(AuthenticationData authenticationData) {
    }

    @Override
    public void doPublishSessionCreation(SessionData sessionData) {
        publishSessionData(sessionData, AuthPublisherConstants.SESSION_CREATION_STATUS);
    }

    @Override
    public void doPublishSessionTermination(SessionData sessionData) {
        publishSessionData(sessionData, AuthPublisherConstants.SESSION_TERMINATION_STATUS);

    }

    @Override
    public void doPublishSessionUpdate(SessionData sessionData) {
        publishSessionData(sessionData, AuthPublisherConstants.SESSION_UPDATE_STATUS);
    }

    @Override
    public String getName() {
        return AuthPublisherConstants.DAS_SESSION_PUBLISHER_NAME;
    }

    /**
     * Add default values if the values coming in are null or empty
     *
     * @param name  Name of the property configured in identity.xml
     * @param value In coming value
     * @return
     */
    protected String replaceIfNotAvailable(String name, String value) {
        if (StringUtils.isNotEmpty(name) && StringUtils.isEmpty(value)) {
            String defaultValue = IdentityUtil.getProperty(AuthPublisherConstants.CONFIG_PREFIX + name);
            if (defaultValue != null) {
                return defaultValue;
            }
        }
        if (StringUtils.isEmpty(value)) {
            return AuthPublisherConstants.NOT_AVAILABLE;
        }
        return value;
    }

    protected void publishSessionData(SessionData sessionData, int actionId) {

        if (sessionData != null) {
            Object[] payloadData = new Object[11];
            payloadData[0] = replaceIfNotAvailable(AuthPublisherConstants.SESSION_ID, sessionData.getSessionId());
            payloadData[1] = sessionData.getCreatedTimestamp();
            payloadData[2] = sessionData.getUpdatedTimestamp();
            payloadData[3] = sessionData.getTerminationTimestamp();
            payloadData[4] = actionId;
            payloadData[5] = replaceIfNotAvailable(AuthPublisherConstants.USERNAME, sessionData.getUser());
            payloadData[6] = replaceIfNotAvailable(AuthPublisherConstants.USER_STORE_DOMAIN, sessionData
                    .getUserStoreDomain());
            payloadData[7] = sessionData.getRemoteIP();
            payloadData[8] = sessionData.getTenantDomain();
            payloadData[9] = sessionData.isRememberMe();
            payloadData[10] = System.currentTimeMillis();

            if (LOG.isDebugEnabled()) {
                for (int i = 0; i < 10; i++) {
                    if (payloadData[i] != null) {
                        LOG.debug("Payload data for entry " + i + " " + payloadData[i].toString());
                    } else {
                        LOG.debug("Payload data for entry " + i + " is null");
                    }

                }
            }
            Event event = new Event(AuthPublisherConstants.SESSION_DATA_STREAM_NAME, System.currentTimeMillis(), null, null,
                    payloadData);
            AuthenticationDataPublisherDataHolder.getInstance().getPublisherService().publish(event);
        }
    }
}
