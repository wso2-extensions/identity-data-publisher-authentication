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

import javax.servlet.http.HttpServletRequest;
import java.util.Iterator;
import java.util.Map;

/*
 * Handle data publishing for analytics
 */
public class AnalyticsSessionDataPublishHandler extends AbstractEventHandler {
    private static final Log LOG = LogFactory.getLog(AnalyticsSessionDataPublishHandler.class);

    private static String getCommaSeparatedIDPs(SessionContext sessionContext) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Retrieving current IDPw for user ");
        }
        if (sessionContext == null || sessionContext.getAuthenticatedIdPs() == null || sessionContext
                .getAuthenticatedIdPs().isEmpty()) {
            return StringUtils.EMPTY;
        }

        Iterator iterator = sessionContext.getAuthenticatedIdPs().entrySet().iterator();
        StringBuilder sb = new StringBuilder();
        while (iterator.hasNext()) {
            Map.Entry pair = (Map.Entry) iterator.next();
            sb.append(",").append(pair.getKey());
        }
        if (sb.length() > 0) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Returning roles, " + sb.substring(1));
            }
            return sb.substring(1); //remove the first comma
        }
        return StringUtils.EMPTY;
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
        if (event != null){
            Map<String, Object> properties = event.getEventProperties();
            HttpServletRequest request = (HttpServletRequest) properties.get(IdentityEventConstants.EventProperty.REQUEST);
            Map<String, Object> params = (Map<String, Object>) properties.get(IdentityEventConstants.EventProperty.PARAMS);
            SessionContext sessionContext = (SessionContext) properties.get(IdentityEventConstants.EventProperty.SESSION_CONTEXT);
            AuthenticationContext context = (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.CONTEXT);

            try {
                Object[] payloadData = getObjects(actionId, request, params, sessionContext, context);

                String[] publishingDomains = this.getPublishingDomains(context, params);
                publishData(payloadData, publishingDomains);

            } catch (IdentityRuntimeException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.error("Error while publishing session information", e);
                }
            }
        }
    }

    /**
     * Create payload needed for publishing the data
     * @param actionId - the session state
     * @param request - the HttpServletRequestObject
     * @param params - parameters in the event
     * @param sessionContext - session context
     * @param context - authentication context
     * @return
     */
    private Object[] getObjects(int actionId, HttpServletRequest request, Map<String, Object> params,
                                SessionContext sessionContext, AuthenticationContext context) {

        Object[] payloadData = new Object[15];
        payloadData[0] = SessionDataPublisherUtil.replaceIfNotAvailable(SessionDataPublisherConstants.CONFIG_PREFIX +
                SessionDataPublisherConstants.SESSION_ID, this.getSessionId(params));
        payloadData[1] = this.getCreatedTimestamp(sessionContext);
        payloadData[2] = this.getUpdatedTimestamp(sessionContext, actionId);
        payloadData[3] = this.getTerminationTimestamp(sessionContext, context, actionId);
        payloadData[4] = actionId;
        payloadData[5] = SessionDataPublisherUtil.replaceIfNotAvailable(SessionDataPublisherConstants.CONFIG_PREFIX +
                SessionDataPublisherConstants.USERNAME, this.getUser(params));
        payloadData[6] = SessionDataPublisherUtil.replaceIfNotAvailable(SessionDataPublisherConstants.CONFIG_PREFIX +
                SessionDataPublisherConstants.USER_STORE_DOMAIN, this.getUserStoreDomain(params));
        payloadData[7] = this.getRemoteIp(request);
        payloadData[8] = SessionDataPublisherConstants.NOT_AVAILABLE;
        payloadData[9] = this.getTenantDomain(params);
        payloadData[10] = this.getServiceProvider(context);
        payloadData[11] = this.getIdentityProviders(sessionContext);
        payloadData[12] = this.isRememberMe(sessionContext);
        payloadData[13] = this.getUserAgent(request);
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
     * @param payloadData - populated payload with session data
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


    private String getSessionId(Map<String, Object> params) {
        return (String) params.get(FrameworkConstants.AnalyticsAttributes.SESSION_ID);
    }

    private String getUser(Map<String, Object> params) {
        String userName = null;
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        if (userObj != null && userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            userName = user.getUserName();
        }
        return userName;
    }

    private String getUserStoreDomain(Map<String, Object> params) {
        String userStoreDomain = null;
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        if (userObj != null && userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            userStoreDomain = user.getUserStoreDomain();
        }
        return userStoreDomain;
    }

    private String getRemoteIp(HttpServletRequest request) {
        String remoteIp = null;
        if (request != null) {
            remoteIp = IdentityUtil.getClientIpAddress(request);
        }
        return remoteIp;
    }

    private String getTenantDomain(Map<String, Object> params) {
        String tenantDomain = null;
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        if (userObj != null && userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            tenantDomain = user.getTenantDomain();
        }
        return tenantDomain;
    }

    private String getServiceProvider(AuthenticationContext context) {
        String serviceProvider = null;
        if (context != null) {
            serviceProvider = context.getServiceProviderName();
        }
        return serviceProvider;
    }

    private String getIdentityProviders(SessionContext context) {
        String identityProviders = null;
        if (context != null) {
            identityProviders = getCommaSeparatedIDPs(context);
        }

        return identityProviders;
    }

    private boolean isRememberMe(SessionContext context) {
        return context.isRememberMe();
    }

    private Long getCreatedTimestamp(SessionContext sessionContext) {
        Long createdTime = null;
        if (sessionContext != null) {
            Object createdTimeObj = sessionContext.getProperty(FrameworkConstants.CREATED_TIMESTAMP);
            createdTime = (Long) createdTimeObj;
        }
        return createdTime;
    }

    private Long getUpdatedTimestamp(SessionContext sessionContext, int actionId) {
        Long updatedTimestamp = null;
        if (SessionDataPublisherConstants.SESSION_CREATION_STATUS == actionId) {
            updatedTimestamp = this.getCreatedTimestamp(sessionContext);
        } else if (SessionDataPublisherConstants.SESSION_UPDATE_STATUS == actionId ||
                SessionDataPublisherConstants.SESSION_TERMINATION_STATUS == actionId) {
            updatedTimestamp = System.currentTimeMillis();
        }
        return updatedTimestamp;
    }


    private Long getTerminationTimestamp(SessionContext sessionContext, AuthenticationContext context, int actionId) {
        Long terminationTime = null;
        if (SessionDataPublisherConstants.SESSION_CREATION_STATUS == actionId ||
                SessionDataPublisherConstants.SESSION_UPDATE_STATUS == actionId) {
            Long createTimestamp = this.getCreatedTimestamp(sessionContext);
            terminationTime = SessionDataPublisherUtil.getSessionExpirationTime(createTimestamp, createTimestamp,
                    context.getTenantDomain(), this.isRememberMe(sessionContext));
        } else if (SessionDataPublisherConstants.SESSION_TERMINATION_STATUS == actionId) {
            terminationTime = System.currentTimeMillis();
        }
        return terminationTime;
    }

    private String getUserAgent(HttpServletRequest request) {
        return request.getHeader(SessionDataPublisherConstants.USER_AGENT);
    }


    private String[] getPublishingDomains(AuthenticationContext context, Map<String, Object> params) {
        String[] publishingDomains;
        if (context.getSequenceConfig().getApplicationConfig().isSaaSApp()) {
            publishingDomains = SessionDataPublisherUtil
                    .getTenantDomains(context.getTenantDomain(), getTenantDomain(params));
        } else {
            publishingDomains = new String[]{getTenantDomain(params)};
        }
        return publishingDomains;
    }


}
