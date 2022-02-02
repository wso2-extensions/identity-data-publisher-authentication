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
import org.slf4j.MDC;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.data.publisher.authentication.audit.model.AuthenticationAuditData;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;

import java.util.Map;

/**
 * Log the authentication login data.
 */
public class AuthenticationAuditLoggingHandler extends AbstractEventHandler {

    private static final Log AUDIT_LOG = CarbonConstants.AUDIT_LOG;
    private static final Log LOG = LogFactory.getLog(AuthenticationAuditLoggingHandler.class);

    public static final String USER_AGENT_QUERY_KEY = "User-Agent";
    public static final String USER_AGENT_KEY = "User Agent";
    public static final String REMOTE_ADDRESS_QUERY_KEY = "remoteAddress";
    public static final String REMOTE_ADDRESS_KEY = "RemoteAddress";
    public static final String USER_STORE_DOMAIN_KEY = "UserStoreDomain";

    @Override
    public String getName() {

        return AuthenticationAuditLoggerConstants.AUTHENTICATION_AUDIT_LOGGER;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        boolean isEnabled = isAuthenticationAuditLoggingEnabled(event);
        boolean isUserNameEnabled = isAuditLoggerUserNameEnabled(event);

        if (!isEnabled) {
            return;
        }

        AuthenticationAuditData authenticationAuditData = null;
        if (IdentityEventConstants.EventName.AUTHENTICATION_STEP_SUCCESS.name().equals(event.getEventName())) {
            authenticationAuditData = AuthenticationAuditLoggerUtils.createAuthenticationAudiDataObject(event,
                    AuthenticationAuditLoggerConstants.AUDIT_AUTHENTICATION_STEP, isUserNameEnabled);
            doPublishAuthenticationStepSuccess(authenticationAuditData);

        } else if (IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name().equals(event.getEventName())) {
            authenticationAuditData = AuthenticationAuditLoggerUtils.createAuthenticationAudiDataObject(event,
                    AuthenticationAuditLoggerConstants.AUDIT_AUTHENTICATION_STEP, isUserNameEnabled);
            doPublishAuthenticationStepFailure(authenticationAuditData);

        } else if (IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name().equals(event.getEventName())) {
            authenticationAuditData = AuthenticationAuditLoggerUtils.createAuthenticationAudiDataObject(event,
                    AuthenticationAuditLoggerConstants.AUDIT_AUTHENTICATION, isUserNameEnabled);
            doPublishAuthenticationSuccess(authenticationAuditData);

        } else if (IdentityEventConstants.EventName.AUTHENTICATION_FAILURE.name().equals(event.getEventName())) {
            authenticationAuditData = AuthenticationAuditLoggerUtils.createAuthenticationAudiDataObject(event,
                    AuthenticationAuditLoggerConstants.AUDIT_AUTHENTICATION, isUserNameEnabled);
            doPublishAuthenticationFailure(authenticationAuditData);

        } else if (IdentityEventConstants.EventName.SESSION_TERMINATE.name().equals(event.getEventName())) {
            publishSessionTermination(event);
        } else {
            LOG.error("Event " + event.getEventName() + " cannot be handled");
        }
    }

    protected void doPublishAuthenticationStepSuccess(AuthenticationAuditData authenticationData) {

        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + authenticationData.getContextIdentifier()
                + "\",\"" + "AuthenticatedUser" + "\" : \"" + authenticationData.getAuthenticatedUser()
                + "\",\"" + "AuthenticatedUserTenantDomain" + "\" : \"" + authenticationData.getTenantDomain()
                + "\",\"" + "ServiceProviderName" + "\" : \"" + authenticationData.getServiceProvider()
                + "\",\"" + "RequestType" + "\" : \"" + authenticationData.getInboundProtocol()
                + "\",\"" + "RelyingParty" + "\" : \"" + authenticationData.getRelyingParty()
                + "\",\"" + "AuthenticatedIdP" + "\" : \"" + authenticationData.getAuthenticatedIdps()
                + "\"";
        auditData = addContextualInfo(auditData, authenticationData);

        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                authenticationData.getAuthenticatedUser(),
                "LoginStepSuccess",
                "ApplicationAuthenticationFramework", auditData, FrameworkConstants.AUDIT_SUCCESS));

    }

    protected void doPublishAuthenticationStepFailure(AuthenticationAuditData authenticationData) {

        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + authenticationData.getContextIdentifier()
                + "\",\"" + "ServiceProviderName" + "\" : \"" + authenticationData.getServiceProvider()
                + "\",\"" + "RequestType" + "\" : \"" + authenticationData.getInboundProtocol()
                + "\",\"" + "RelyingParty" + "\" : \"" + authenticationData.getRelyingParty()
                + "\",\"" + "StepNo" + "\" : \"" + authenticationData.getStepNo()
                + "\"";
        auditData = addContextualInfo(auditData, authenticationData);

        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                authenticationData.getAuthenticatedUser(),
                "Login",
                "ApplicationAuthenticationFramework", auditData, FrameworkConstants.AUDIT_FAILED));
    }

    protected void doPublishAuthenticationSuccess(AuthenticationAuditData authenticationData) {

        AuthenticationResult authenticationResult = new AuthenticationResult();
        authenticationResult.setAuthenticated(true);
        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + authenticationData.getContextIdentifier()
                + "\",\"" + "AuthenticatedUser" + "\" : \"" + authenticationData.getAuthenticatedUser()
                + "\",\"" + "AuthenticatedUserTenantDomain" + "\" : \"" + authenticationData.getTenantDomain()
                + "\",\"" + "ServiceProviderName" + "\" : \"" + authenticationData.getServiceProvider()
                + "\",\"" + "RequestType" + "\" : \"" + authenticationData.getInboundProtocol()
                + "\",\"" + "RelyingParty" + "\" : \"" + authenticationData.getRelyingParty()
                + "\",\"" + "AuthenticatedIdPs" + "\" : \"" + authenticationData.getAuthenticatedIdps()
                + "\"";
        auditData = addContextualInfo(auditData, authenticationData);

        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                authenticationData.getAuthenticatedUser(),
                "Login",
                "ApplicationAuthenticationFramework", auditData, FrameworkConstants.AUDIT_SUCCESS));
    }

    protected void doPublishAuthenticationFailure(AuthenticationAuditData authenticationData) {

        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + authenticationData.getContextIdentifier()
                + "\",\"" + "ServiceProviderName" + "\" : \"" + authenticationData.getServiceProvider()
                + "\",\"" + "RequestType" + "\" : \"" + authenticationData.getInboundProtocol()
                + "\",\"" + "RelyingParty" + "\" : \"" + authenticationData.getRelyingParty()
                + "\",\"" + "StepNo" + "\" : \"" + authenticationData.getStepNo()
                + "\"";
        auditData = addContextualInfo(auditData, authenticationData);

        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                authenticationData.getAuthenticatedUser(),
                "Login",
                "ApplicationAuthenticationFramework", auditData, FrameworkConstants.AUDIT_FAILED));
    }

    protected void doPublishSessionTermination(AuthenticationContext context, String username,
                                               String tenantDomain, String authenticatedIDPs) {

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

    protected void publishSessionTermination(Event event) {

        Map<String, Object> properties = event.getEventProperties();
        SessionContext sessionContext = (SessionContext) properties.get(IdentityEventConstants.EventProperty.
                SESSION_CONTEXT);
        AuthenticationContext context = (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.
                CONTEXT);

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

        doPublishSessionTermination(context, username, tenantDomain, authenticatedIDPs);
    }

    private boolean isAuthenticationAuditLoggingEnabled(Event event) throws IdentityEventException {

        if (this.configs.getModuleProperties() != null) {
            String handlerEnabled = this.configs.getModuleProperties().getProperty(AuthenticationAuditLoggerConstants.
                    AUTHENTICATION_AUDIT_LOGGER_ENABLED);
            return Boolean.parseBoolean(handlerEnabled);
        }

        return false;
    }

    private boolean isAuditLoggerUserNameEnabled(Event event) throws IdentityEventException {

        boolean isEnabled = false;
        if (this.configs.getModuleProperties() != null) {
            String handlerEnabled = this.configs.getModuleProperties().getProperty(AuthenticationAuditLoggerConstants.
                    AUTHENTICATION_AUDIT_LOGGER_USERNAME_ENABLED);
            if (StringUtils.isNotBlank(handlerEnabled) && handlerEnabled.equals("username")) {
                isEnabled = true;
            }
        }
        return isEnabled;
    }

    private String addContextualInfo(String data, AuthenticationAuditData authenticationData) {

        data += ",\"" + USER_AGENT_KEY + "\" : \"" + MDC.get(USER_AGENT_QUERY_KEY)
                + "\",\"" + REMOTE_ADDRESS_KEY + "\" : \"" + MDC.get(REMOTE_ADDRESS_QUERY_KEY)
                + "\",\"" + USER_STORE_DOMAIN_KEY + "\" : \"" + authenticationData.getUserStoreDomain()
                + "\"";
        return data;
    }
}
