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

package org.wso2.carbon.identity.data.publisher.authentication.analytics.login;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthPublisherConstants;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthnDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.login.model.AuthenticationData;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;

/**
 * Utils for Analytics Login data publisher.
 */
public class AnalyticsLoginDataPublisherUtils {

    private static final String APPLICATION_DOMAIN = "Application";
    private static final String WORKFLOW_DOMAIN = "Workflow";
    private static final String INTERNAL_EVERYONE_ROLE = "Internal/everyone";

    /**
     * Build authentication data object for authentication step from event.
     *
     * @param event
     * @return Authentication data object
     */
    public static AuthenticationData buildAuthnDataForAuthnStep(Event event) {

        Map<String, Object> properties = event.getEventProperties();
        HttpServletRequest request = (HttpServletRequest) properties.get(IdentityEventConstants.EventProperty.REQUEST);
        Map<String, Object> params = (Map<String, Object>) properties.get(IdentityEventConstants.EventProperty.PARAMS);
        AuthenticationContext context = (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.
                CONTEXT);
        AuthenticatorStatus status = (AuthenticatorStatus) properties.get(IdentityEventConstants.EventProperty.
                AUTHENTICATION_STATUS);

        AuthenticationData authenticationData = new AuthenticationData();
        setIdpForAuthnStep(context, authenticationData);
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        setUserDataForAuthnStep(authenticationData, userObj);

        Object isFederatedObj = params.get(FrameworkConstants.AnalyticsAttributes.IS_FEDERATED);
        setIdpTypeForAuthnStep(authenticationData, isFederatedObj);

        authenticationData.setContextId(context.getContextIdentifier());
        authenticationData.setEventId(UUID.randomUUID().toString());
        authenticationData.setEventType(AnalyticsLoginDataPublishConstants.STEP_EVENT);
        authenticationData.setAuthnSuccess(false);
        authenticationData.setRemoteIp(getRemoteIP(request));
        authenticationData.setServiceProvider(context.getServiceProviderName());
        authenticationData.setInboundProtocol(context.getRequestType());
        authenticationData.setRememberMe(context.isRememberMe());
        authenticationData.setForcedAuthn(context.isForceAuthenticate());
        authenticationData.setPassive(context.isPassiveAuthenticate());
        authenticationData.setInitialLogin(false);
        authenticationData.setAuthenticator(context.getCurrentAuthenticator());
        authenticationData.setSuccess(AuthenticatorStatus.PASS == status);
        authenticationData.setStepNo(context.getCurrentStep());

        setTenantDataForIdpStep(context, status, authenticationData);

        authenticationData.addParameter(AuthPublisherConstants.RELYING_PARTY, context.getRelyingParty());
        return authenticationData;
    }

    private static void setTenantDataForIdpStep(AuthenticationContext context, AuthenticatorStatus status,
                                                AuthenticationData authenticationData) {

        if (AuthenticatorStatus.PASS == status) {
            authenticationData.addParameter(AnalyticsLoginDataPublishConstants.TENANT_DOMAIN_NAMES,
                    AuthnDataPublisherUtils.getTenantDomains(context.getTenantDomain(), authenticationData.
                            getTenantDomain()));
        } else {
            // Should publish the event to both SP tenant domain and the tenant domain of the user who did the login
            // attempt
            if (context.getSequenceConfig() != null && context.getSequenceConfig().getApplicationConfig() != null
                    && context.getSequenceConfig().getApplicationConfig().isSaaSApp()) {
                authenticationData.addParameter(AnalyticsLoginDataPublishConstants.TENANT_DOMAIN_NAMES,
                        AuthnDataPublisherUtils.getTenantDomains(context.getTenantDomain(), authenticationData.
                                getTenantDomain()));
            } else {
                authenticationData.addParameter(AnalyticsLoginDataPublishConstants.TENANT_DOMAIN_NAMES,
                        AuthnDataPublisherUtils.getTenantDomains(context.getTenantDomain(), null));
            }

        }
    }

    private static void setIdpTypeForAuthnStep(AuthenticationData authenticationData, Object isFederatedObj) {

        if (isFederatedObj != null) {
            boolean isFederated = (Boolean) isFederatedObj;
            if (isFederated) {
                authenticationData.setIdentityProviderType(FrameworkConstants.FEDERATED_IDP_NAME);
            } else {
                authenticationData.setIdentityProviderType(FrameworkConstants.LOCAL_IDP_NAME);
                authenticationData.setLocalUsername(authenticationData.getUsername());
            }
        }
    }

    private static void setUserDataForAuthnStep(AuthenticationData authenticationData, Object userObj) {

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
    }

    private static void setIdpForAuthnStep(AuthenticationContext context, AuthenticationData authenticationData) {

        if (context.getExternalIdP() == null) {
            authenticationData.setIdentityProvider(FrameworkConstants.LOCAL_IDP_NAME);
        } else {
            authenticationData.setIdentityProvider(context.getExternalIdP().getIdPName());
        }
    }

    /**
     * Build authentication data object for authentication from event.
     *
     * @param event - triggerd event
     * @return AuthenticationData - authentication data object
     */
    public static AuthenticationData buildAuthnDataForAuthentication(Event event) {

        Map<String, Object> properties = event.getEventProperties();
        HttpServletRequest request = (HttpServletRequest) properties.get(IdentityEventConstants.EventProperty.REQUEST);
        Map<String, Object> params = (Map<String, Object>) properties.get(IdentityEventConstants.EventProperty.PARAMS);
        AuthenticationContext context = (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.
                CONTEXT);
        AuthenticatorStatus status = (AuthenticatorStatus) properties.get(IdentityEventConstants.EventProperty.
                AUTHENTICATION_STATUS);

        AuthenticationData authenticationData = new AuthenticationData();
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        setUserDataForAuthentication(authenticationData, userObj);

        authenticationData = setIdpDataAndStepForAuthentication(context, status, authenticationData);

        authenticationData.setEventType(AnalyticsLoginDataPublishConstants.OVERALL_EVENT);
        authenticationData.setContextId(context.getContextIdentifier());
        authenticationData.setEventId(UUID.randomUUID().toString());
        if (AuthenticatorStatus.PASS.equals(status)) {
            authenticationData.setAuthnSuccess(true);
        } else if (AuthenticatorStatus.FAIL.equals(status)) {
            authenticationData.setAuthnSuccess(false);
        }
        authenticationData.setRemoteIp(getRemoteIP(request));
        authenticationData.setServiceProvider(context.getServiceProviderName());
        authenticationData.setInboundProtocol(context.getRequestType());
        authenticationData.setRememberMe(context.isRememberMe());
        authenticationData.setForcedAuthn(context.isForceAuthenticate());
        authenticationData.setPassive(context.isPassiveAuthenticate());

        setTenantDataForAuthentication(context, status, authenticationData);

        authenticationData.addParameter(AuthPublisherConstants.RELYING_PARTY, context.getRelyingParty());

        return authenticationData;
    }

    private static void setTenantDataForAuthentication(AuthenticationContext context, AuthenticatorStatus status,
                                                       AuthenticationData authenticationData) {

        if (status == AuthenticatorStatus.PASS) {
            authenticationData.addParameter(AnalyticsLoginDataPublishConstants.TENANT_DOMAIN_NAMES,
                    AuthnDataPublisherUtils.getTenantDomains(context.getTenantDomain(), authenticationData.
                            getTenantDomain()));
            authenticationData.addParameter(AuthPublisherConstants.SUBJECT_IDENTIFIER,
                    context.getSequenceConfig().getAuthenticatedUser().getAuthenticatedSubjectIdentifier());
            authenticationData.addParameter(AuthPublisherConstants.AUTHENTICATED_IDPS,
                    context.getSequenceConfig().getAuthenticatedIdPs());
        } else {
            // Should publish the event to both SP tenant domain and the tenant domain of the user who did the login
            // attempt
            if (context.getSequenceConfig() != null && context.getSequenceConfig().getApplicationConfig
                    () != null && context.getSequenceConfig().getApplicationConfig().isSaaSApp()) {
                authenticationData.addParameter(AnalyticsLoginDataPublishConstants.TENANT_DOMAIN_NAMES,
                        AuthnDataPublisherUtils.getTenantDomains(context.getTenantDomain(), authenticationData.
                                getTenantDomain()));
            } else {
                authenticationData.addParameter(AnalyticsLoginDataPublishConstants.TENANT_DOMAIN_NAMES,
                        AuthnDataPublisherUtils.getTenantDomains(context.getTenantDomain(), null));
            }
        }
    }

    private static AuthenticationData setIdpDataAndStepForAuthentication(AuthenticationContext context,
                                                                         AuthenticatorStatus status,
                                                                         AuthenticationData authenticationData) {

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
        authenticationData.setInitialLogin(isInitialLogin);

        return authenticationData;
    }

    private static void setUserDataForAuthentication(AuthenticationData authenticationData,
            Object userObj) {

        if (userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            authenticationData.setUsername(user.getUserName());
            authenticationData.setTenantDomain(user.getTenantDomain());
            authenticationData.setUserStoreDomain(user.getUserStoreDomain());
        }
    }

    private static AuthenticationData fillLocalEvent(AuthenticationData authenticationData,
                                                     AuthenticationContext context) {

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

    private static String getRemoteIP(HttpServletRequest request) {

        if (request != null) {
            return IdentityUtil.getClientIpAddress(request);
        } else {
            return AuthPublisherConstants.NOT_AVAILABLE;
        }
    }
}
