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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.data.publisher.authentication.audit.Model.AuthenticationAuditData;
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

    @Override
    public String getName(){
        return AuthenticationAuditLoggerConstants.AUTHENTICATION_AUDIT_LOGGER;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        AuthenticationAuditData authenticationAuditData = null;
        if (event.getEventName().equals(IdentityEventConstants.EventName.AUTHENTICATION_STEP_SUCCESS.name())) {
            authenticationAuditData = AuthenticationAuditLoggerUtils
                    .createAuthenticationAudiDataObject(event, AuthenticationAuditLoggerConstants.AUDIT_AUTHENTICATION_STEP);
            doPublishAuthenticationStepSuccess(authenticationAuditData);

        } else if (event.getEventName().equals(IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name())) {
            authenticationAuditData = AuthenticationAuditLoggerUtils
                    .createAuthenticationAudiDataObject(event, AuthenticationAuditLoggerConstants.AUDIT_AUTHENTICATION_STEP);
            doPublishAuthenticationStepFailure(authenticationAuditData);

        } else if (event.getEventName().equals(IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name())) {
            authenticationAuditData = AuthenticationAuditLoggerUtils
                    .createAuthenticationAudiDataObject(event, AuthenticationAuditLoggerConstants.AUDIT_AUTHENTICATION);
            doPublishAuthenticationSuccess(authenticationAuditData);

        } else if (event.getEventName().equals(IdentityEventConstants.EventName.AUTHENTICATION_FAILURE.name())) {
            authenticationAuditData = AuthenticationAuditLoggerUtils
                    .createAuthenticationAudiDataObject(event, AuthenticationAuditLoggerConstants.AUDIT_AUTHENTICATION);
            doPublishAuthenticationFailure(authenticationAuditData);

        } else if (event.getEventName().equals(IdentityEventConstants.EventName.SESSION_TERMINATE.name())) {
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
                + "\",\"" + "AuthenticatedIdP" + "\" : \"" + authenticationData.getAuthenticatedIdp()
                + "\"";

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

        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                null,
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
