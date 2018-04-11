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
import org.wso2.carbon.identity.data.publisher.authentication.analytics.session.model.SessionData;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.idp.mgt.util.IdPManagementUtil;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.servlet.http.HttpServletRequest;

/*
 * Utils for Analytics session data publish handler
 */
public class SessionDataPublisherUtil {

    public static final String NOT_AVAILABLE = "NOT_AVAILABLE";
    private static final Log LOG = LogFactory.getLog(SessionDataPublisherUtil.class);

    /**
     * Add default values if the values coming in are null or empty
     *
     * @param name  Name of the property configured in identity.xml
     * @param value In coming value
     * @return
     */
    public static String replaceIfNotAvailable(String name, String value) {

        if (StringUtils.isNotEmpty(name) && StringUtils.isEmpty(value)) {
            String defaultValue = IdentityUtil.getProperty(name);
            if (defaultValue != null) {
                return defaultValue;
            }
        }
        if (StringUtils.isEmpty(value)) {
            return SessionDataPublisherUtil.NOT_AVAILABLE;
        }
        return value;
    }

    /**
     * Get the expiration time of the session
     *
     * @param createdTime  Created time of the session
     * @param updatedTime  Updated time of the session
     * @param tenantDomain Tenant Domain
     * @param isRememberMe Whether remember me is enabled
     * @return Session expiration time
     */
    public static long getSessionExpirationTime(long createdTime, long updatedTime, String tenantDomain,
                                                boolean isRememberMe) {
        // If remember me is enabled, Session termination time will be fixed
        if (isRememberMe) {
            long rememberMeTimeout = TimeUnit.SECONDS.toMillis(IdPManagementUtil.getRememberMeTimeout(tenantDomain));
            return createdTime + rememberMeTimeout;
        }
        long idleSessionTimeOut = TimeUnit.SECONDS.toMillis(IdPManagementUtil.getIdleSessionTimeOut(tenantDomain));
        return idleSessionTimeOut + updatedTime;
    }

    public static String[] getTenantDomains(String spTenantDomain, String userTenantDomain) {

        if (StringUtils.isBlank(userTenantDomain) || userTenantDomain.equalsIgnoreCase(SessionDataPublisherConstants
                .NOT_AVAILABLE)) {
            return new String[]{spTenantDomain};
        }
        if (StringUtils.isBlank(spTenantDomain) || userTenantDomain.equalsIgnoreCase(SessionDataPublisherConstants
                .NOT_AVAILABLE)) {
            return new String[]{userTenantDomain};
        }
        if (spTenantDomain.equalsIgnoreCase(userTenantDomain)) {
            return new String[]{userTenantDomain};
        } else {
            return new String[]{userTenantDomain, spTenantDomain};
        }
    }

    /**
     * Get metadata array for different tenants with tenant domain
     *
     * @param tenantDomain
     * @return
     */
    public static Object[] getMetaDataArray(String tenantDomain) {

        Object[] metaData = new Object[1];
        if (StringUtils.isBlank(tenantDomain)) {
            metaData[0] = MultitenantConstants.SUPER_TENANT_ID;
        } else {
            metaData[0] = IdentityTenantUtil.getTenantId(tenantDomain);
        }
        return metaData;
    }

    /**
     * Create the session data object to pupulate payload of event
     * @param event - triggered event object from framework
     * @return
     */
    public static SessionData buildSessionData(Event event) {

        Map<String, Object> properties = event.getEventProperties();
        HttpServletRequest request = (HttpServletRequest) properties.get(IdentityEventConstants.EventProperty.REQUEST);
        Map<String, Object> params = (Map<String, Object>) properties.get(IdentityEventConstants.EventProperty.PARAMS);
        SessionContext sessionContext = (SessionContext) properties.get(IdentityEventConstants.EventProperty.SESSION_CONTEXT);
        AuthenticationContext context = (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.CONTEXT);

        SessionData sessionData = new SessionData();
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        String sessionId = (String) params.get(FrameworkConstants.AnalyticsAttributes.SESSION_ID);
        String userName = null;
        String userStoreDomain = null;
        String tenantDomain = null;
        if (userObj != null && userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            userName = user.getUserName();
            userStoreDomain = user.getUserStoreDomain();
            tenantDomain = user.getTenantDomain();
        }
        sessionData.setSessionContext(sessionContext);
        sessionData.setUser(userName);
        sessionData.setUserStoreDomain(userStoreDomain);
        sessionData.setTenantDomain(tenantDomain);
        sessionData.setSessionId(sessionId);
        sessionData.setIdentityProviders(getCommaSeparatedIDPs(sessionContext));
        sessionData.setUserAgent(request.getHeader(SessionDataPublisherConstants.USER_AGENT));
        if (sessionContext != null) {
            sessionData.setIsRememberMe(sessionContext.isRememberMe());
        }
        if (context != null) {
            sessionData.setServiceProvider(context.getServiceProviderName());
        }
        if (request != null) {
            sessionData.setRemoteIP(IdentityUtil.getClientIpAddress(request));
        }
        if(context != null && context.getSequenceConfig() != null) {
            if (context.getSequenceConfig().getApplicationConfig().isSaaSApp()) {
                sessionData.addParameter(SessionDataPublisherConstants.TENANT_ID, SessionDataPublisherUtil
                        .getTenantDomains(context.getTenantDomain(), sessionData.getTenantDomain()));
            } else {
                sessionData.addParameter(SessionDataPublisherConstants.TENANT_ID, new String[]{sessionData.getTenantDomain()});
            }
        }

        return sessionData;
    }


    public static void updateTimeStamps(SessionData sessionData,int actionId){
        SessionContext sessionContext = sessionData.getSessionContext();
        Long createdTime = null;
        Long terminationTime = null;
        Long updatedTime = null;
        if(sessionContext != null) {
            Object createdTimeObj = sessionContext.getProperty(FrameworkConstants.CREATED_TIMESTAMP);
            createdTime = (Long) createdTimeObj;
            if (actionId == SessionDataPublisherConstants.SESSION_CREATION_STATUS) {
                terminationTime = SessionDataPublisherUtil.getSessionExpirationTime(createdTime, createdTime,
                        sessionData.getTenantDomain(), sessionContext.isRememberMe());
                updatedTime = createdTime;

            } else if (actionId == SessionDataPublisherConstants.SESSION_UPDATE_STATUS) {
                Long currentTime = System.currentTimeMillis();
                terminationTime = SessionDataPublisherUtil.getSessionExpirationTime(createdTime, createdTime,
                        sessionData.getTenantDomain(), sessionContext.isRememberMe());
                updatedTime = currentTime;

            } else if (actionId == SessionDataPublisherConstants.SESSION_TERMINATION_STATUS) {
                Long currentTime = System.currentTimeMillis();
                terminationTime = currentTime;
                updatedTime = currentTime;
            }
            sessionData.setCreatedTimestamp(createdTime);
            sessionData.setUpdatedTimestamp(updatedTime);
            sessionData.setTerminationTimestamp(terminationTime);
        }



    }

    public static String getCommaSeparatedIDPs(SessionContext sessionContext) {

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
