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
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthPublisherConstants;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthnDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.session.model.SessionData;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.idp.mgt.util.IdPManagementUtil;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.servlet.http.HttpServletRequest;

/**
 * Utils for Analytics session data publish handler.
 */
public class SessionDataPublisherUtil {

    private static final Log LOG = LogFactory.getLog(SessionDataPublisherUtil.class);

    /**
     * Create the session data object to pupulate payload of event.
     *
     * @param event - triggered event object from framework
     * @return
     */
    public static SessionData buildSessionData(Event event) {

        Map<String, Object> properties = event.getEventProperties();
        HttpServletRequest request = (HttpServletRequest) properties.get(IdentityEventConstants.EventProperty.REQUEST);
        Map<String, Object> params = (Map<String, Object>) properties.get(IdentityEventConstants.EventProperty.PARAMS);
        SessionContext sessionContext = (SessionContext) properties.get(IdentityEventConstants.EventProperty.
                SESSION_CONTEXT);
        AuthenticationContext context = (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.
                CONTEXT);

        SessionData sessionData = new SessionData();
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        setUserDataToSessionObject(sessionData, userObj);

        String sessionId = (String) params.get(FrameworkConstants.AnalyticsAttributes.SESSION_ID);
        sessionData.setSessionId(sessionId);
        sessionData.setSessionContext(sessionContext);
        sessionData.setIdentityProviders(getCommaSeparatedIDPs(sessionContext));

        if (sessionContext != null) {
            sessionData.setIsRememberMe(sessionContext.isRememberMe());
        }
        if (context != null) {
            setTenantDataToSessionObject(context, sessionData);
            sessionData.setServiceProvider(context.getServiceProviderName());
        }
        if (request != null) {
            sessionData.setUserAgent(request.getHeader(AuthPublisherConstants.USER_AGENT));
            sessionData.setRemoteIP(IdentityUtil.getClientIpAddress(request));
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("A Session data object created for event :" + event.getEventName());
        }

        return sessionData;
    }

    /**
     * Populate the tenant details from authentication context.
     *
     * @param context
     * @param sessionData
     */
    private static void setTenantDataToSessionObject(AuthenticationContext context, SessionData sessionData) {

        if (context.getSequenceConfig() != null) {
            if (context.getSequenceConfig().getApplicationConfig().isSaaSApp()) {
                sessionData.addParameter(AuthPublisherConstants.TENANT_ID, AuthnDataPublisherUtils
                        .getTenantDomains(context.getTenantDomain(), sessionData.getTenantDomain()));
            } else {
                sessionData.addParameter(AuthPublisherConstants.TENANT_ID, new String[]{sessionData.
                        getTenantDomain()});
            }
        }
    }

    /**
     * Populate user data from user object from paramerters.
     *
     * @param sessionData
     * @param userObj
     */
    private static void setUserDataToSessionObject(SessionData sessionData, Object userObj) {

        String userName = null;
        String userStoreDomain = null;
        String tenantDomain = null;
        if (userObj != null && userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            userName = user.getUserName();
            userStoreDomain = user.getUserStoreDomain();
            tenantDomain = user.getTenantDomain();
        }
        sessionData.setUser(userName);
        sessionData.setUserStoreDomain(userStoreDomain);
        sessionData.setTenantDomain(tenantDomain);
    }

    /**
     * Update the timestamps of the session in respect to the action.
     *
     * @param sessionData
     * @param actionId
     */
    public static void updateTimeStamps(SessionData sessionData, int actionId) {

        SessionContext sessionContext = null;
        if (sessionData != null) {
            sessionContext = sessionData.getSessionContext();
        }
        Long createdTime = null;
        Long terminationTime = null;
        Long updatedTime = null;
        if (sessionContext != null) {
            Object createdTimeObj = sessionContext.getProperty(FrameworkConstants.CREATED_TIMESTAMP);
            createdTime = (Long) createdTimeObj;
            if (actionId == SessionDataPublisherConstants.SESSION_CREATION_STATUS) {
                terminationTime = AuthnDataPublisherUtils.getSessionExpirationTime(createdTime, createdTime,
                        sessionData.getTenantDomain(), sessionContext.isRememberMe());
                updatedTime = createdTime;

            } else if (actionId == SessionDataPublisherConstants.SESSION_UPDATE_STATUS) {
                Long currentTime = System.currentTimeMillis();
                terminationTime = AuthnDataPublisherUtils.getSessionExpirationTime(createdTime, createdTime,
                        sessionData.getTenantDomain(), sessionContext.isRememberMe());
                updatedTime = currentTime;

            } else if (actionId == SessionDataPublisherConstants.SESSION_TERMINATION_STATUS) {
                Long currentTime = System.currentTimeMillis();
                terminationTime = currentTime;
                updatedTime = currentTime;
            }

        }
        if (sessionData != null) {
            sessionData.setCreatedTimestamp(createdTime);
            sessionData.setUpdatedTimestamp(updatedTime);
            sessionData.setTerminationTimestamp(terminationTime);
        }

    }

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
}
