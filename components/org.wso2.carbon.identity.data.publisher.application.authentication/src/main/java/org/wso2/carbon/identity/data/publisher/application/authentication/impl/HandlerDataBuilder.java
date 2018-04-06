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
 *
 */

package org.wso2.carbon.identity.data.publisher.application.authentication.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthPublisherConstants;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthnDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.application.authentication.model.AuthenticationData;
import org.wso2.carbon.identity.data.publisher.application.authentication.model.SessionData;
import org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty;
import org.wso2.carbon.identity.event.event.Event;

import javax.servlet.http.HttpServletRequest;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

/*
 * The class builds dtos needed for event handling of publishers
 */
public class HandlerDataBuilder {
    private static final Log log = LogFactory.getLog(HandlerDataBuilder.class);

    public static SessionData buildSessionData(Event event) {

        Map<String, Object> properties = event.getEventProperties();
        HttpServletRequest request = (HttpServletRequest) properties.get(EventProperty.REQUEST);
        Map<String, Object> params = (Map<String, Object>) properties.get(EventProperty.PARAMS);
        SessionContext sessionContext = (SessionContext) properties.get(EventProperty.SESSION_CONTEXT);
        AuthenticationContext context = (AuthenticationContext) properties.get(EventProperty.CONTEXT);

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
        sessionData.setUser(userName);
        sessionData.setUserStoreDomain(userStoreDomain);
        sessionData.setTenantDomain(tenantDomain);
        sessionData.setSessionId(sessionId);
        sessionData.setIdentityProviders(getCommaSeparatedIDPs(sessionContext));
        if (sessionContext != null) {
            sessionData.setIsRememberMe(sessionContext.isRememberMe());
        }
        if (context != null) {
            sessionData.setServiceProvider(context.getServiceProviderName());
        }
        if (request != null) {
            sessionData.setRemoteIP(IdentityUtil.getClientIpAddress(request));
        }

        return sessionData;
    }


    private static String getCommaSeparatedIDPs(SessionContext sessionContext) {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving current IDPw for user ");
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
            if (log.isDebugEnabled()) {
                log.debug("Returning roles, " + sb.substring(1));
            }
            return sb.substring(1); //remove the first comma
        }
        return StringUtils.EMPTY;
    }

    public static AuthenticationData buildAuthnDataForAuthnStep(Event event) {

        Map<String, Object> properties = event.getEventProperties();
        HttpServletRequest request = (HttpServletRequest) properties.get(EventProperty.REQUEST);
        Map<String, Object> params = (Map<String, Object>) properties.get(EventProperty.PARAMS);
        AuthenticationContext context = (AuthenticationContext) properties.get(EventProperty.CONTEXT);
        AuthenticatorStatus status = (AuthenticatorStatus) properties.get(EventProperty.AUTHENTICATION_STATUS);

        AuthenticationData authenticationData = new AuthenticationData();
        int step = context.getCurrentStep();
        if (context.getExternalIdP() == null) {
            authenticationData.setIdentityProvider(FrameworkConstants.LOCAL_IDP_NAME);
        } else {
            authenticationData.setIdentityProvider(context.getExternalIdP().getIdPName());
        }
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        if (userObj instanceof User) {
            User user = (User) userObj;
            authenticationData.setTenantDomain(user.getTenantDomain());
            authenticationData.setUserStoreDomain(user.getUserStoreDomain());
            authenticationData.setUsername(user.getUserName());
        }
        if (userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            if (StringUtils.isEmpty(user.getUserName())) {
                authenticationData.setUsername(user.getAuthenticatedSubjectIdentifier());
            }
        }

        Object isFederatedObj = params.get(FrameworkConstants.AnalyticsAttributes.IS_FEDERATED);
        if (isFederatedObj != null) {
            boolean isFederated = (Boolean) isFederatedObj;
            if (isFederated) {
                authenticationData.setIdentityProviderType(FrameworkConstants.FEDERATED_IDP_NAME);
            } else {
                authenticationData.setIdentityProviderType(FrameworkConstants.LOCAL_IDP_NAME);
                authenticationData.setLocalUsername(authenticationData.getUsername());
            }
        }
        authenticationData.setContextId(context.getContextIdentifier());
        authenticationData.setEventId(UUID.randomUUID().toString());
        authenticationData.setEventType(AuthPublisherConstants.STEP_EVENT);
        authenticationData.setAuthnSuccess(false);
        authenticationData.setRemoteIp(IdentityUtil.getClientIpAddress(request));
        authenticationData.setServiceProvider(context.getServiceProviderName());
        authenticationData.setInboundProtocol(context.getRequestType());
        authenticationData.setRememberMe(context.isRememberMe());
        authenticationData.setForcedAuthn(context.isForceAuthenticate());
        authenticationData.setPassive(context.isPassiveAuthenticate());
        authenticationData.setInitialLogin(false);
        authenticationData.setAuthenticator(context.getCurrentAuthenticator());
        authenticationData.setSuccess(AuthenticatorStatus.PASS == status);
        authenticationData.setStepNo(step);

        if (AuthenticatorStatus.PASS == status) {
            authenticationData.addParameter(AuthPublisherConstants.TENANT_ID, AuthnDataPublisherUtils
                    .getTenantDomains(context.getTenantDomain(), authenticationData.getTenantDomain()));
        } else {
            // Should publish the event to both SP tenant domain and the tenant domain of the user who did the login
            // attempt
            if (context.getSequenceConfig() != null && context.getSequenceConfig().getApplicationConfig() != null && context
                    .getSequenceConfig().getApplicationConfig().isSaaSApp()) {
                authenticationData.addParameter(AuthPublisherConstants.TENANT_ID, AuthnDataPublisherUtils
                        .getTenantDomains(context.getTenantDomain(), authenticationData.getTenantDomain()));
            } else {
                authenticationData.addParameter(AuthPublisherConstants.TENANT_ID, AuthnDataPublisherUtils
                        .getTenantDomains(context.getTenantDomain(), null));
            }

        }

        authenticationData.addParameter(AuthPublisherConstants.RELYING_PARTY, context.getRelyingParty());
        return authenticationData;
    }

    public static AuthenticationData buildAuthnDataForAuthentication(Event event) {

        Map<String, Object> properties = event.getEventProperties();
        HttpServletRequest request = (HttpServletRequest) properties.get(EventProperty.REQUEST);
        Map<String, Object> params = (Map<String, Object>) properties.get(EventProperty.PARAMS);
        AuthenticationContext context = (AuthenticationContext) properties.get(EventProperty.CONTEXT);
        AuthenticatorStatus status = (AuthenticatorStatus) properties.get(EventProperty.AUTHENTICATION_STATUS);

        AuthenticationData authenticationData = new AuthenticationData();
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        if (userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            authenticationData.setUsername(user.getUserName());
            if (status == AuthenticatorStatus.FAIL) {
                authenticationData.setTenantDomain(user.getTenantDomain());
                authenticationData.setUserStoreDomain(user.getUserStoreDomain());
            }
        }

        boolean isInitialLogin = false;

        if (status == AuthenticatorStatus.PASS) {
            Object hasFederatedStepObj = context.getProperty(FrameworkConstants.AnalyticsAttributes.HAS_FEDERATED_STEP);
            Object hasLocalStepObj = context.getProperty(FrameworkConstants.AnalyticsAttributes.HAS_LOCAL_STEP);
            Object isInitialLoginObj = context.getProperty(FrameworkConstants.AnalyticsAttributes.IS_INITIAL_LOGIN);
            boolean hasPreviousLocalStep = hasPreviousLocalEvent(context);
            boolean hasFederated = convertToBoolean(hasFederatedStepObj);
            boolean hasLocal = convertToBoolean(hasLocalStepObj);
            isInitialLogin = convertToBoolean(isInitialLoginObj);

            if (!hasPreviousLocalStep && hasFederated && hasLocal) {
                authenticationData.setIdentityProviderType(FrameworkConstants.FEDERATED_IDP_NAME + "," +
                        FrameworkConstants.LOCAL_IDP_NAME);
                authenticationData.setStepNo(getLocalStepNo(context));
            } else if (!hasPreviousLocalStep && hasLocal) {
                authenticationData.setIdentityProviderType(FrameworkConstants.LOCAL_IDP_NAME);
                authenticationData.setStepNo(getLocalStepNo(context));
            } else if (hasFederated) {
                authenticationData.setIdentityProviderType(FrameworkConstants.FEDERATED_IDP_NAME);
            }
            authenticationData.setIdentityProvider(AuthnDataPublisherUtils.getSubjectStepIDP(context));
            authenticationData.setSuccess(true);
            authenticationData = fillLocalEvent(authenticationData, context);

        }

        authenticationData.setEventType(AuthPublisherConstants.OVERALL_EVENT);
        authenticationData.setContextId(context.getContextIdentifier());
        authenticationData.setEventId(UUID.randomUUID().toString());
        authenticationData.setAuthnSuccess(true);
        authenticationData.setRemoteIp(IdentityUtil.getClientIpAddress(request));
        authenticationData.setServiceProvider(context.getServiceProviderName());
        authenticationData.setInboundProtocol(context.getRequestType());
        authenticationData.setRememberMe(context.isRememberMe());
        authenticationData.setForcedAuthn(context.isForceAuthenticate());
        authenticationData.setPassive(context.isPassiveAuthenticate());
        authenticationData.setInitialLogin(isInitialLogin);

        if (status == AuthenticatorStatus.PASS) {
            authenticationData.addParameter(AuthPublisherConstants.TENANT_ID, AuthnDataPublisherUtils
                    .getTenantDomains(context.getTenantDomain(), authenticationData.getTenantDomain()));
            authenticationData.addParameter(AuthPublisherConstants.SUBJECT_IDENTIFIER, context.getSequenceConfig()
                    .getAuthenticatedUser().getAuthenticatedSubjectIdentifier());
            authenticationData.addParameter(AuthPublisherConstants.AUTHENTICATED_IDPS, context.getSequenceConfig()
                    .getAuthenticatedIdPs());
        } else {
            // Should publish the event to both SP tenant domain and the tenant domain of the user who did the login
            // attempt
            if (context.getSequenceConfig() != null && context.getSequenceConfig().getApplicationConfig
                    () != null && context.getSequenceConfig().getApplicationConfig().isSaaSApp()) {
                authenticationData.addParameter(AuthPublisherConstants.TENANT_ID, AuthnDataPublisherUtils
                        .getTenantDomains(context.getTenantDomain(), authenticationData.getTenantDomain()));
            } else {
                authenticationData.addParameter(AuthPublisherConstants.TENANT_ID, AuthnDataPublisherUtils
                        .getTenantDomains(context.getTenantDomain(), null));
            }
        }

        authenticationData.addParameter(AuthPublisherConstants.RELYING_PARTY, context.getRelyingParty());

        return authenticationData;
    }

    private static AuthenticationData fillLocalEvent(AuthenticationData authenticationData, AuthenticationContext context) {
        AuthenticatedIdPData localIDPData = null;
        Map<String, AuthenticatedIdPData> previousAuthenticatedIDPs = context.getPreviousAuthenticatedIdPs();
        Map<String, AuthenticatedIdPData> currentAuthenticatedIDPs = context.getCurrentAuthenticatedIdPs();
        if (currentAuthenticatedIDPs != null && currentAuthenticatedIDPs.size() > 0) {
            localIDPData = currentAuthenticatedIDPs.get(FrameworkConstants.LOCAL_IDP_NAME);
        }
        if (localIDPData == null && previousAuthenticatedIDPs != null && previousAuthenticatedIDPs.size() > 0) {
            localIDPData = previousAuthenticatedIDPs.get(FrameworkConstants.LOCAL_IDP_NAME);
        }

        if (localIDPData != null) {
            authenticationData.setLocalUsername(localIDPData.getUser().getAuthenticatedSubjectIdentifier());
            authenticationData.setUserStoreDomain(localIDPData.getUser().getUserStoreDomain());
            authenticationData.setTenantDomain(localIDPData.getUser().getTenantDomain());
            authenticationData.setAuthenticator(localIDPData.getAuthenticator().getName());
        }
        return authenticationData;
    }

    private static boolean hasPreviousLocalEvent(AuthenticationContext context) {
        Map<String, AuthenticatedIdPData> previousAuthenticatedIDPs = context.getPreviousAuthenticatedIdPs();
        if (previousAuthenticatedIDPs.get(FrameworkConstants.LOCAL_IDP_NAME) != null) {
            return true;
        }
        return false;
    }

    private static boolean convertToBoolean(Object object) {
        if (object != null) {
            return (Boolean) object;
        }
        return false;
    }

    private static int getLocalStepNo(AuthenticationContext context) {
        int stepNo = 0;
        Map<Integer, StepConfig> map = context.getSequenceConfig().getStepMap();
        for (Map.Entry<Integer, StepConfig> entry : map.entrySet()) {
            StepConfig stepConfig = entry.getValue();
            if (stepConfig != null && FrameworkConstants.LOCAL_IDP_NAME.equalsIgnoreCase(stepConfig
                    .getAuthenticatedIdP())) {
                stepNo = entry.getKey();
                return stepNo;
            }
        }
        return stepNo;
    }
}
