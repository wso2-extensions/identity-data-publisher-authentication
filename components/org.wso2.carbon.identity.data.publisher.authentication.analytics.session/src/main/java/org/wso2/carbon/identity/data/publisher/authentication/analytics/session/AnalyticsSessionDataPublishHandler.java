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
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;

/*
 * Handle data publishing for analytics
 */
public class AnalyticsSessionDataPublishHandler extends AbstractEventHandler {

    private static final Log LOG = LogFactory.getLog(AnalyticsSessionDataPublishHandler.class);
    private Map<String, Object> params;
    private AuthenticationContext context;
    private HttpServletRequest request;
    private SessionContext sessionContext;
    private int actionId;

    private void init(Event event, int actionid) {

        Map<String, Object> properties = event.getEventProperties();
        this.request = (HttpServletRequest) properties.get(IdentityEventConstants.EventProperty.REQUEST);
        this.params = (Map<String, Object>) properties.get(IdentityEventConstants.EventProperty.PARAMS);
        this.sessionContext = (SessionContext) properties.get(IdentityEventConstants.EventProperty.SESSION_CONTEXT);
        this.context = (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.CONTEXT);
        this.actionId = actionid;
    }

    private String getSessionId() {

        return (String) this.params.get(FrameworkConstants.AnalyticsAttributes.SESSION_ID);
    }

    private String getUser() {

        String userName = null;
        Object userObj = this.params.get(FrameworkConstants.AnalyticsAttributes.USER);
        if (userObj != null && userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            userName = user.getUserName();
        }
        return userName;
    }

    private String getUserStoreDomain() {

        String userStoreDomain = null;
        Object userObj = this.params.get(FrameworkConstants.AnalyticsAttributes.USER);
        if (userObj != null && userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            userStoreDomain = user.getUserStoreDomain();
        }
        return userStoreDomain;
    }

    private String getRemoteIp() {

        String remoteIp = null;
        if (this.request != null) {
            remoteIp = IdentityUtil.getClientIpAddress(this.request);
        }
        return remoteIp;
    }

    private String getTenantDomain() {

        String tenantDomain = null;
        Object userObj = this.params.get(FrameworkConstants.AnalyticsAttributes.USER);
        if (userObj != null && userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            tenantDomain = user.getTenantDomain();
        }
        return tenantDomain;
    }

    private String getServiceProvider() {

        String serviceProvider = null;
        if (this.context != null) {
            serviceProvider = this.context.getServiceProviderName();
        }
        return serviceProvider;
    }

    private String getIdentityProviders() {

        String identityProviders = null;
        if (this.sessionContext != null) {
            identityProviders = SessionDataPublisherUtil.getCommaSeparatedIDPs(this.sessionContext);
        }

        return identityProviders;
    }

    private boolean isRememberMe() {

        return this.sessionContext.isRememberMe();
    }

    private Long getCreatedTimestamp() {

        Long createdTime = null;
        if (this.sessionContext != null) {
            Object createdTimeObj = this.sessionContext.getProperty(FrameworkConstants.CREATED_TIMESTAMP);
            createdTime = (Long) createdTimeObj;
        }
        return createdTime;
    }

    private Long getUpdatedTimestamp() {

        Long updatedTimestamp = null;
        if (SessionDataPublisherConstants.SESSION_CREATION_STATUS == this.actionId) {
            updatedTimestamp = this.getCreatedTimestamp();
        } else if (SessionDataPublisherConstants.SESSION_UPDATE_STATUS == this.actionId ||
                SessionDataPublisherConstants.SESSION_TERMINATION_STATUS == this.actionId) {
            updatedTimestamp = System.currentTimeMillis();
        }
        return updatedTimestamp;
    }

    private Long getTerminationTimestamp() {

        Long terminationTime = null;
        if (SessionDataPublisherConstants.SESSION_CREATION_STATUS == this.actionId ||
                SessionDataPublisherConstants.SESSION_UPDATE_STATUS == this.actionId) {
            Long createTimestamp = this.getCreatedTimestamp();
            terminationTime = SessionDataPublisherUtil.getSessionExpirationTime(createTimestamp, createTimestamp,
                    context.getTenantDomain(), this.isRememberMe());
        } else if (SessionDataPublisherConstants.SESSION_TERMINATION_STATUS == actionId) {
            terminationTime = System.currentTimeMillis();
        }
        return terminationTime;
    }

    private String getUserAgent() {

        return this.request.getHeader(SessionDataPublisherConstants.USER_AGENT);
    }

    private String[] getPublishingDomains() {

        String[] publishingDomains;
        if (this.context.getSequenceConfig().getApplicationConfig().isSaaSApp()) {
            publishingDomains = SessionDataPublisherUtil
                    .getTenantDomains(this.context.getTenantDomain(), this.getTenantDomain());
        } else {
            publishingDomains = new String[]{this.getTenantDomain()};
        }
        return publishingDomains;
    }

    /**
     * Create payload needed for publishing the data
     */
    private Object[] populatePayload() {

        Object[] payloadData = new Object[15];
        payloadData[0] = SessionDataPublisherUtil.replaceIfNotAvailable(SessionDataPublisherConstants.CONFIG_PREFIX +
                SessionDataPublisherConstants.SESSION_ID, this.getSessionId());
        payloadData[1] = this.getCreatedTimestamp();
        payloadData[2] = this.getUpdatedTimestamp();
        payloadData[3] = this.getTerminationTimestamp();
        payloadData[4] = this.actionId;
        payloadData[5] = SessionDataPublisherUtil.replaceIfNotAvailable(SessionDataPublisherConstants.CONFIG_PREFIX +
                SessionDataPublisherConstants.USERNAME, this.getUser());
        payloadData[6] = SessionDataPublisherUtil.replaceIfNotAvailable(SessionDataPublisherConstants.CONFIG_PREFIX +
                SessionDataPublisherConstants.USER_STORE_DOMAIN, this.getUserStoreDomain());
        payloadData[7] = this.getRemoteIp();
        payloadData[8] = SessionDataPublisherConstants.NOT_AVAILABLE;
        payloadData[9] = this.getTenantDomain();
        payloadData[10] = this.getServiceProvider();
        payloadData[11] = this.getIdentityProviders();
        payloadData[12] = this.isRememberMe();
        payloadData[13] = this.getUserAgent();
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

    /**
     * Publish data to the analytics
     *
     * @param payloadData       - populated payload with session data
     * @param publishingDomains - the domains that should publish
     */
    private void publishData(Object[] payloadData, String[] publishingDomains) {

        if (publishingDomains != null && publishingDomains.length > 0) {
            try {
                FrameworkUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                for (String publishingDomain : publishingDomains) {
                    Object[] metadataArray = SessionDataPublisherUtil.getMetaDataArray(publishingDomain);
                    org.wso2.carbon.databridge.commons.Event publishingEvent =
                            new org.wso2.carbon.databridge.commons.Event(SessionDataPublisherConstants
                                    .SESSION_DATA_STREAM_NAME, System
                                    .currentTimeMillis(), metadataArray, null, payloadData);
//                            AuthenticationDataPublisherDataHolder.getInstance().getPublisherService().publish(publishingEvent);
                    if (LOG.isDebugEnabled() && publishingEvent != null) {
                        LOG.debug("Sending out event : " + publishingEvent.toString());
                    }
                }
            } finally {
                FrameworkUtils.endTenantFlow();
            }
        }
    }

    @Override
    public String getName() {

        return SessionDataPublisherConstants.ANALYTICS_SESSION_PUBLISHER_NAME;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        if (event.getEventName().equals(IdentityEventConstants.EventName.SESSION_CREATE.name())) {
            doPublishSessionCreation(event);
        } else if (event.getEventName().equals(IdentityEventConstants.EventName.SESSION_TERMINATE.name())) {
            doPublishSessionTermination(event);
        } else if (event.getEventName().equals(IdentityEventConstants.EventName.SESSION_UPDATE.name())) {
            doPublishSessionUpdate(event);
        } else {
            LOG.error("Event " + event.getEventName() + " cannot be handled");
        }
    }

    protected void doPublishSessionCreation(Event event) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Publishing session creation to DAS");
        }
        publishSessionData(event, SessionDataPublisherConstants.SESSION_CREATION_STATUS);
    }

    protected void doPublishSessionTermination(Event event) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Publishing session termination to DAS");
        }
        publishSessionData(event, SessionDataPublisherConstants.SESSION_TERMINATION_STATUS);

    }

    protected void doPublishSessionUpdate(Event event) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Publishing session update to DAS");
        }
        publishSessionData(event, SessionDataPublisherConstants.SESSION_UPDATE_STATUS);
    }

    protected void publishSessionData(Event event, int actionId) {

        init(event, actionId);
        if (event != null) {

            try {
                Object[] payloadData = populatePayload();

                String[] publishingDomains = getPublishingDomains();
                publishData(payloadData, publishingDomains);

            } catch (IdentityRuntimeException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.error("Error while publishing session information", e);
                }
            }
        }
    }

}
