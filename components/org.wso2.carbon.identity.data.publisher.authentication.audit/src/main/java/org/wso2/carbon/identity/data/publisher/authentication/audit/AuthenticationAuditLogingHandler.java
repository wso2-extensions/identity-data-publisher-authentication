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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;

import java.util.Map;

/*
 * Log the authentication login data
 */
public class AuthenticationAuditLogingHandler extends AbstractEventHandler {
    private static final Log AUDIT_LOG = CarbonConstants.AUDIT_LOG;
    private static final Log LOG = LogFactory.getLog(AuthenticationAuditLogingHandler.class);

    private static String getContextIdentifier(Map<String, Object> properties) {
        AuthenticationContext context = getAuthenticationContextFromProperties(properties);
        return context.getContextIdentifier();
    }

    private static String getUserNameForAuthenticationStep(Map<String, Object> properties) {
        String userName = null;
        Map<String, Object> params = getParamsFromProperties(properties);
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        if (userObj instanceof User) {
            User user = (User) userObj;
            userName = user.getUserName();
        }
        if (userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            if (StringUtils.isEmpty(user.getUserName())) {
                userName = user.getAuthenticatedSubjectIdentifier();
            }
        }
        return userName;
    }


    private static String getTenantDomainForAuthenticationStep(Map<String, Object> properties) {
        String tenantDomain = null;
        Map<String, Object> params = getParamsFromProperties(properties);
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        if (userObj instanceof User) {
            User user = (User) userObj;
            tenantDomain = user.getTenantDomain();
        }
        return tenantDomain;
    }

    private static String getTenantDomainForAuthentication(Map<String, Object> properties) {
        String tenantDomain = null;
        Map<String, Object> params = getParamsFromProperties(properties);
        AuthenticatorStatus status = getAutheticatorStatusFromProperties(properties);
        AuthenticationContext context = getAuthenticationContextFromProperties(properties);
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
        }
        return tenantDomain;
    }

    private static String getServiceProvider(Map<String, Object> properties) {
        AuthenticationContext context = getAuthenticationContextFromProperties(properties);
        return context.getServiceProviderName();
    }

    private static String getInboundProtocol(Map<String, Object> properties) {
        AuthenticationContext context = getAuthenticationContextFromProperties(properties);
        return context.getRequestType();
    }

    private static String getRelyingParty(Map<String, Object> properties) {
        AuthenticationContext context = getAuthenticationContextFromProperties(properties);
        return context.getRelyingParty();
    }

    private static String getIdentityProviderForAuthenticationStep(Map<String, Object> properties) {
        String idpProvider = null;
        AuthenticationContext context = getAuthenticationContextFromProperties(properties);
        if (context.getExternalIdP() == null) {
            idpProvider = FrameworkConstants.LOCAL_IDP_NAME;
        } else {
            idpProvider = context.getExternalIdP().getIdPName();
        }
        return idpProvider;
    }

    private static int getStepNoForAutheticationStep(Map<String, Object> properties) {
        AuthenticationContext context = getAuthenticationContextFromProperties(properties);
        return context.getCurrentStep();
    }

    private static int getStepNoForAuthentication(Map<String, Object> properties) {
        int step = 0;
        AuthenticationContext context = getAuthenticationContextFromProperties(properties);
        AuthenticatorStatus status = (AuthenticatorStatus) properties.get(IdentityEventConstants.EventProperty.AUTHENTICATION_STATUS);
        if (status == AuthenticatorStatus.PASS) {
            Object hasFederatedStepObj = context.getProperty(FrameworkConstants.AnalyticsAttributes.HAS_FEDERATED_STEP);
            Object hasLocalStepObj = context.getProperty(FrameworkConstants.AnalyticsAttributes.HAS_LOCAL_STEP);
            boolean hasPreviousLocalStep = hasPreviousLocalEvent(context);
            boolean hasFederated = convertToBoolean(hasFederatedStepObj);
            boolean hasLocal = convertToBoolean(hasLocalStepObj);

            if (!hasPreviousLocalStep && hasFederated && hasLocal) {
                step = getLocalStepNo(context);
            } else if (!hasPreviousLocalStep && hasLocal) {
                step = getLocalStepNo(context);
            }
        }
        return step;
    }

    private static String getSubjectIdentifier(Map<String, Object> properties) {
        String subjectIdentifier = null;
        AuthenticatorStatus status = getAutheticatorStatusFromProperties(properties);
        AuthenticationContext context = getAuthenticationContextFromProperties(properties);
        if (status == AuthenticatorStatus.PASS) {
            subjectIdentifier = context.getSequenceConfig().getAuthenticatedUser().getAuthenticatedSubjectIdentifier();
        }
        return subjectIdentifier;
    }

    private static String getIdenitityProviderList(Map<String, Object> properties) {
        String authenticatedIdps = null;
        AuthenticatorStatus status = getAutheticatorStatusFromProperties(properties);
        AuthenticationContext context = getAuthenticationContextFromProperties(properties);
        if (status == AuthenticatorStatus.PASS) {
            authenticatedIdps = context.getSequenceConfig().getAuthenticatedIdPs();
        }
        return authenticatedIdps;
    }

    private static Map<String, Object> getParamsFromProperties(Map<String, Object> properties) {
        return (Map<String, Object>) properties.get(IdentityEventConstants.EventProperty.PARAMS);
    }

    private static AuthenticationContext getAuthenticationContextFromProperties(Map<String, Object> properties) {
        return (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.CONTEXT);
    }

    private static AuthenticatorStatus getAutheticatorStatusFromProperties(Map<String, Object> properties) {
        return (AuthenticatorStatus) properties.get(IdentityEventConstants.EventProperty.AUTHENTICATION_STATUS);
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

    @Override
    public void handleEvent(Event event) throws IdentityEventException {
        Map<String, Object> properties = event.getEventProperties();
        if (event.getEventName().equals(IdentityEventConstants.EventName.AUTHENTICATION_STEP_SUCCESS.name())) {
            doPublishAuthenticationStepSuccess(properties);
        } else if (event.getEventName().equals(IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name())) {
            doPublishAuthenticationStepFailure(properties);
        } else if (event.getEventName().equals(IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name())) {
            doPublishAuthenticationSuccess(properties);
        } else if (event.getEventName().equals(IdentityEventConstants.EventName.AUTHENTICATION_FAILURE.name())) {
            doPublishAuthenticationFailure(properties);
        } else if (event.getEventName().equals(IdentityEventConstants.EventName.SESSION_TERMINATE.name())) {
            publishSessionTermination(event);
        } else {
            LOG.error("Event " + event.getEventName() + " cannot be handled");
        }
    }

    protected void doPublishAuthenticationStepSuccess(Map<String, Object> properties) {

        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + getContextIdentifier(properties)
                + "\",\"" + "AuthenticatedUser" + "\" : \"" + getUserNameForAuthenticationStep(properties)
                + "\",\"" + "AuthenticatedUserTenantDomain" + "\" : \"" + getTenantDomainForAuthenticationStep(properties)
                + "\",\"" + "ServiceProviderName" + "\" : \"" + getServiceProvider(properties)
                + "\",\"" + "RequestType" + "\" : \"" + getInboundProtocol(properties)
                + "\",\"" + "RelyingParty" + "\" : \"" + getRelyingParty(properties)
                + "\",\"" + "AuthenticatedIdP" + "\" : \"" + getIdentityProviderForAuthenticationStep(properties)
                + "\"";

        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                getUserNameForAuthenticationStep(properties),
                "LoginStepSuccess",
                "ApplicationAuthenticationFramework", auditData, FrameworkConstants.AUDIT_SUCCESS));


    }

    protected void doPublishAuthenticationStepFailure(Map<String, Object> properties) {

        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + getContextIdentifier(properties)
                + "\",\"" + "ServiceProviderName" + "\" : \"" + getServiceProvider(properties)
                + "\",\"" + "RequestType" + "\" : \"" + getInboundProtocol(properties)
                + "\",\"" + "RelyingParty" + "\" : \"" + getRelyingParty(properties)
                + "\",\"" + "StepNo" + "\" : \"" + getStepNoForAutheticationStep(properties)
                + "\"";

        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                null,
                "Login",
                "ApplicationAuthenticationFramework", auditData, FrameworkConstants.AUDIT_FAILED));
    }

    protected void doPublishAuthenticationSuccess(Map<String, Object> properties) {

        AuthenticationResult authenticationResult = new AuthenticationResult();
        authenticationResult.setAuthenticated(true);
        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + getContextIdentifier(properties)
                + "\",\"" + "AuthenticatedUser" + "\" : \"" + getSubjectIdentifier(properties)
                + "\",\"" + "AuthenticatedUserTenantDomain" + "\" : \"" + getTenantDomainForAuthentication(properties)
                + "\",\"" + "ServiceProviderName" + "\" : \"" + getServiceProvider(properties)
                + "\",\"" + "RequestType" + "\" : \"" + getInboundProtocol(properties)
                + "\",\"" + "RelyingParty" + "\" : \"" + getRelyingParty(properties)
                + "\",\"" + "AuthenticatedIdPs" + "\" : \"" + getIdenitityProviderList(properties)
                + "\"";

        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                getSubjectIdentifier(properties),
                "Login",
                "ApplicationAuthenticationFramework", auditData, FrameworkConstants.AUDIT_SUCCESS));
    }

    protected void doPublishAuthenticationFailure(Map<String, Object> properties) {
        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + getContextIdentifier(properties)
                + "\",\"" + "ServiceProviderName" + "\" : \"" + getServiceProvider(properties)
                + "\",\"" + "RequestType" + "\" : \"" + getInboundProtocol(properties)
                + "\",\"" + "RelyingParty" + "\" : \"" + getRelyingParty(properties)
                + "\",\"" + "StepNo" + "\" : \"" + getStepNoForAuthentication(properties)
                + "\"";

        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                null,
                "Login",
                "ApplicationAuthenticationFramework", auditData, FrameworkConstants.AUDIT_FAILED));
    }

    protected void publishSessionTermination(Event event) {
        Map<String, Object> properties = event.getEventProperties();
        SessionContext sessionContext = (SessionContext) properties.get(IdentityEventConstants.EventProperty.SESSION_CONTEXT);
        AuthenticationContext context = (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.CONTEXT);

        if (context == null) {
            return;
        }
        SequenceConfig sequenceConfig = context.getSequenceConfig();
        AuthenticatedUser authenticatedUser = null;
        String username = "";
        String tenantDomain = "";
        String authenticatedIDPs = "";

        if (sequenceConfig != null && sequenceConfig.getAuthenticatedUser() != null) {
            authenticatedUser = sequenceConfig.getAuthenticatedUser();
            authenticatedIDPs = sequenceConfig.getAuthenticatedIdPs();
        } else {
            Object authenticatedUserObj = sessionContext.getProperty(FrameworkConstants.AUTHENTICATED_USER);
            if (authenticatedUserObj != null) {
                authenticatedUser = (AuthenticatedUser) authenticatedUserObj;
            }
        }

        if (authenticatedUser != null) {
            username = authenticatedUser.getAuthenticatedSubjectIdentifier();
            tenantDomain = authenticatedUser.getTenantDomain();
        }

        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + context.getContextIdentifier()
                + "\",\"" + "LoggedOutUser" + "\" : \"" + username
                + "\",\"" + "LoggedOutUserTenantDomain" + "\" : \"" + tenantDomain
                + "\",\"" + "ServiceProviderName" + "\" : \"" + context.getServiceProviderName()
                + "\",\"" + "RequestType" + "\" : \"" + context.getRequestType()
                + "\",\"" + "RelyingParty" + "\" : \"" + context.getRelyingParty()
                + "\",\"" + "AuthenticatedIdPs" + "\" : \"" + authenticatedIDPs
                + "\"";

        String idpName = null;
        ExternalIdPConfig externalIdPConfig = context.getExternalIdP();
        if (externalIdPConfig != null) {
            idpName = externalIdPConfig.getName();
        }
        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                username,
                "Logout", idpName, auditData, FrameworkConstants.AUDIT_SUCCESS));
    }

}
