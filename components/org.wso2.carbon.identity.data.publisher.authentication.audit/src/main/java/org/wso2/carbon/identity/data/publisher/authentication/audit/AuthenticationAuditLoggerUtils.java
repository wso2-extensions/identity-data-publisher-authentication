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

package org.wso2.carbon.identity.data.publisher.authentication.audit;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.data.publisher.authentication.audit.model.AuthenticationAuditData;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Map;

/**
 * Utilities for authentication audit logger.
 */
public class AuthenticationAuditLoggerUtils {

    /**
     * Create authentication data object from event for respective authentication step.
     *
     * @param event             Triggered event.
     * @param authType          Authentication type.
     * @param isUsernameEnabled Is username enable in audit logs.
     * @return Populated AuthenticationAuditData object.
     */
    public static AuthenticationAuditData createAuthenticationAudiDataObject(Event event, String authType,
                                                                             boolean isUsernameEnabled) {

        Map<String, Object> properties = event.getEventProperties();
        AuthenticationContext context = getAuthenticationContextFromProperties(properties);
        Map<String, Object> params = getParamsFromProperties(properties);
        AuthenticatorStatus status = getAuthenticatorStatusFromProperties(properties);

        AuthenticationAuditData authenticationAuditData = new AuthenticationAuditData();

        authenticationAuditData.setContextIdentifier(getContextIdentifier(context));
        authenticationAuditData.setServiceProvider(getServiceProvider(context));
        authenticationAuditData.setInboundProtocol(getInboundProtocol(context));
        authenticationAuditData.setRelyingParty(getRelyingParty(context));
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        setUserStoreDomain(authenticationAuditData, userObj);

        String authenticatedUser = null;
        String username = null;
        String tenantDomain = null;

        if (AuthenticationAuditLoggerConstants.AUDIT_AUTHENTICATION_STEP.equals(authType)) {
            authenticatedUser = getUserNameForAuthenticationStep(params);
            username = authenticatedUser;
            tenantDomain = getTenantDomainForAuthenticationStep(params);
            authenticationAuditData.setAuthenticatedUser(authenticatedUser);
            authenticationAuditData.setTenantDomain(tenantDomain);
            authenticationAuditData.setAuthenticatedIdps(getIdentityProviderForAuthenticationStep(context));
            authenticationAuditData.setStepNo(getStepNoForAuthenticationStep(context));
        } else if (AuthenticationAuditLoggerConstants.AUDIT_AUTHENTICATION.equals(authType)) {
            if (isUsernameEnabled) {
                authenticatedUser = getAuthenticatedUserName(context, status);
                username = authenticatedUser;
                authenticationAuditData.setAuthenticatedUser(authenticatedUser);
            } else {
                authenticatedUser = getSubjectIdentifier(context, status);
                /*
                Tenant aware username is required only if masking logs has been enabled. Added this condition to avoid
                unnecessary method call in the case of masking logs is disabled.
                */
                if (LoggerUtils.isLogMaskingEnable && StringUtils.isNotBlank(authenticatedUser)) {
                    username = MultitenantUtils.getTenantAwareUsername(authenticatedUser);
                }
                authenticationAuditData.setAuthenticatedUser(authenticatedUser);
            }
            tenantDomain = getTenantDomainForAuthentication(context, params, status);
            authenticationAuditData.setTenantDomain(tenantDomain);
            authenticationAuditData.setStepNo(getStepNoForAuthentication(context, status));
            authenticationAuditData.setAuthenticatedIdps(getIdentityProviderList(context, status));
        }
        if (LoggerUtils.isLogMaskingEnable && StringUtils.isNotBlank(tenantDomain) && StringUtils.isNotBlank(username)) {
            /* When username is disabled for audit authentication step, skip user ID resolving as the username is set
            as the authenticated subject identifier which might not be always the username. */
            if (!AuthenticationAuditLoggerConstants.AUDIT_AUTHENTICATION.equals(authType) || isUsernameEnabled) {
                String userId = IdentityUtil.getInitiatorId(username, tenantDomain);
                authenticationAuditData.setUserId(userId);
            }
        }
        return authenticationAuditData;
    }

    private static String getAuthenticatedUserName(AuthenticationContext context, AuthenticatorStatus status) {

        String userName = null;
        if (status == AuthenticatorStatus.PASS) {
            userName = context.getSequenceConfig().getAuthenticatedUser().getUserName();
        }
        return userName;
    }

    private static void setUserStoreDomain(AuthenticationAuditData authenticationAuditData, Object userObj) {

        if (userObj instanceof User) {
            User user = (User) userObj;
            authenticationAuditData.setUserStoreDomain(user.getUserStoreDomain());
        }
    }

    private static String getContextIdentifier(AuthenticationContext context) {

        return context.getContextIdentifier();
    }

    private static String getUserNameForAuthenticationStep(Map<String, Object> params) {

        String userName = null;
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        if (userObj instanceof User) {
            User user = (User) userObj;
            userName = UserCoreUtil.addDomainToName(user.getUserName(), user.getUserStoreDomain());
        }
        if (userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            if (StringUtils.isEmpty(user.getUserName())) {
                userName = user.getAuthenticatedSubjectIdentifier();
            }
        }
        return userName;
    }

    private static String getTenantDomainForAuthenticationStep(Map<String, Object> params) {

        String tenantDomain = null;
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        if (userObj instanceof User) {
            User user = (User) userObj;
            tenantDomain = user.getTenantDomain();
        }
        return tenantDomain;
    }

    private static String getTenantDomainForAuthentication(AuthenticationContext context, Map<String, Object> params,
                                                           AuthenticatorStatus status) {

        String tenantDomain = null;
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        if (userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            if (status == AuthenticatorStatus.FAIL) {
                tenantDomain = user.getTenantDomain();
            }
        }
        if (status == AuthenticatorStatus.PASS) {
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
                tenantDomain = localIDPData.getUser().getTenantDomain();
            }
            if (StringUtils.isBlank(tenantDomain)) {
                tenantDomain = context.getTenantDomain();
            }
        }
        return tenantDomain;
    }

    private static String getServiceProvider(AuthenticationContext context) {

        return context.getServiceProviderName();
    }

    private static String getInboundProtocol(AuthenticationContext context) {

        return context.getRequestType();
    }

    private static String getRelyingParty(AuthenticationContext context) {

        return context.getRelyingParty();
    }

    private static String getIdentityProviderForAuthenticationStep(AuthenticationContext context) {

        String idpProvider = null;
        if (context.getExternalIdP() == null) {
            idpProvider = FrameworkConstants.LOCAL_IDP_NAME;
        } else {
            idpProvider = context.getExternalIdP().getIdPName();
        }
        return idpProvider;
    }

    private static int getStepNoForAuthenticationStep(AuthenticationContext context) {

        return context.getCurrentStep();
    }

    private static int getStepNoForAuthentication(AuthenticationContext context, AuthenticatorStatus status) {

        int step = 0;
        if (status == AuthenticatorStatus.PASS) {
            Object hasLocalStepObj = context.getProperty(FrameworkConstants.AnalyticsAttributes.HAS_LOCAL_STEP);
            boolean hasPreviousLocalStep = hasPreviousLocalEvent(context);
            boolean hasLocal = convertToBoolean(hasLocalStepObj);

            if (!hasPreviousLocalStep && hasLocal) {
                step = getLocalStepNo(context);
            }
        }
        return step;
    }

    private static String getSubjectIdentifier(AuthenticationContext context, AuthenticatorStatus status) {

        String subjectIdentifier = null;
        if (status == AuthenticatorStatus.PASS) {
            subjectIdentifier = context.getSequenceConfig().getAuthenticatedUser().getAuthenticatedSubjectIdentifier();
        }
        return subjectIdentifier;
    }

    private static String getIdentityProviderList(AuthenticationContext context, AuthenticatorStatus status) {

        String authenticatedIdps = null;
        if (status == AuthenticatorStatus.PASS) {
            authenticatedIdps = context.getSequenceConfig().getAuthenticatedIdPs();
        }
        return authenticatedIdps;
    }

    private static AuthenticationContext getAuthenticationContextFromProperties(Map<String, Object> properties) {

        return (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.CONTEXT);
    }

    private static AuthenticatorStatus getAuthenticatorStatusFromProperties(Map<String, Object> properties) {

        return (AuthenticatorStatus) properties.get(IdentityEventConstants.EventProperty.AUTHENTICATION_STATUS);
    }

    private static SessionContext getSessionContextFromProperties(Map<String, Object> properties) {

        return (SessionContext) properties.get(IdentityEventConstants.EventProperty.SESSION_CONTEXT);
    }

    private static Map<String, Object> getParamsFromProperties(Map<String, Object> properties) {

        return (Map<String, Object>) properties.get(IdentityEventConstants.EventProperty.PARAMS);
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
