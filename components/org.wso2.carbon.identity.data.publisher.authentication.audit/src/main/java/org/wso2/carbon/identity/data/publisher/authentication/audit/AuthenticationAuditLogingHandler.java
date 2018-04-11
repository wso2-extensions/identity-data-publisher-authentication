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
    private AuthenticationContext context;
    private Map<String, Object> params;
    private AuthenticatorStatus status;
    private SessionContext sessionContext;

    private void init(Event event) {

        Map<String, Object> properties = event.getEventProperties();
        this.context = AuthenticationAuditLoggerUtils.getAuthenticationContextFromProperties(properties);
        this.params = AuthenticationAuditLoggerUtils.getParamsFromProperties(properties);
        this.status = AuthenticationAuditLoggerUtils.getAutheticatorStatusFromProperties(properties);
        this.sessionContext = AuthenticationAuditLoggerUtils.getSessionContextFromProperties(properties);

    }

    private String getContextIdentifier() {

        return this.context.getContextIdentifier();
    }

    private String getUserNameForAuthenticationStep() {

        String userName = null;
        Object userObj = this.params.get(FrameworkConstants.AnalyticsAttributes.USER);
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

    private String getTenantDomainForAuthenticationStep() {

        String tenantDomain = null;
        Object userObj = this.params.get(FrameworkConstants.AnalyticsAttributes.USER);
        if (userObj instanceof User) {
            User user = (User) userObj;
            tenantDomain = user.getTenantDomain();
        }
        return tenantDomain;
    }

    private String getTenantDomainForAuthentication() {

        String tenantDomain = null;
        Object userObj = this.params.get(FrameworkConstants.AnalyticsAttributes.USER);
        if (userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            if (this.status == AuthenticatorStatus.FAIL) {
                tenantDomain = user.getTenantDomain();
            }
        }
        if (this.status == AuthenticatorStatus.PASS) {
            AuthenticatedIdPData localIDPData = null;
            Map<String, AuthenticatedIdPData> previousAuthenticatedIDPs = this.context.getPreviousAuthenticatedIdPs();
            Map<String, AuthenticatedIdPData> currentAuthenticatedIDPs = this.context.getCurrentAuthenticatedIdPs();
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

    private String getServiceProvider() {

        return this.context.getServiceProviderName();
    }

    private String getInboundProtocol() {

        return this.context.getRequestType();
    }

    private String getRelyingParty() {

        return this.context.getRelyingParty();
    }

    private String getIdentityProviderForAuthenticationStep() {

        String idpProvider = null;
        if (this.context.getExternalIdP() == null) {
            idpProvider = FrameworkConstants.LOCAL_IDP_NAME;
        } else {
            idpProvider = this.context.getExternalIdP().getIdPName();
        }
        return idpProvider;
    }

    private int getStepNoForAutheticationStep() {

        return context.getCurrentStep();
    }

    private int getStepNoForAuthentication() {

        int step = 0;
        if (this.status == AuthenticatorStatus.PASS) {
            Object hasLocalStepObj = this.context.getProperty(FrameworkConstants.AnalyticsAttributes.HAS_LOCAL_STEP);
            boolean hasPreviousLocalStep = AuthenticationAuditLoggerUtils.hasPreviousLocalEvent(this.context);
            boolean hasLocal = AuthenticationAuditLoggerUtils.convertToBoolean(hasLocalStepObj);

            if (!hasPreviousLocalStep && hasLocal) {
                step = AuthenticationAuditLoggerUtils.getLocalStepNo(this.context);
            }
        }
        return step;
    }

    private String getSubjectIdentifier() {

        String subjectIdentifier = null;
        if (this.status == AuthenticatorStatus.PASS) {
            subjectIdentifier = this.context.getSequenceConfig().getAuthenticatedUser().getAuthenticatedSubjectIdentifier();
        }
        return subjectIdentifier;
    }

    private String getIdenitityProviderList() {

        String authenticatedIdps = null;
        if (this.status == AuthenticatorStatus.PASS) {
            authenticatedIdps = this.context.getSequenceConfig().getAuthenticatedIdPs();
        }
        return authenticatedIdps;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        this.init(event);
        if (event.getEventName().equals(IdentityEventConstants.EventName.AUTHENTICATION_STEP_SUCCESS.name())) {
            doPublishAuthenticationStepSuccess();
        } else if (event.getEventName().equals(IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name())) {
            doPublishAuthenticationStepFailure();
        } else if (event.getEventName().equals(IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name())) {
            doPublishAuthenticationSuccess();
        } else if (event.getEventName().equals(IdentityEventConstants.EventName.AUTHENTICATION_FAILURE.name())) {
            doPublishAuthenticationFailure();
        } else if (event.getEventName().equals(IdentityEventConstants.EventName.SESSION_TERMINATE.name())) {
            publishSessionTermination();
        } else {
            LOG.error("Event " + event.getEventName() + " cannot be handled");
        }
    }

    protected void doPublishAuthenticationStepSuccess() {

        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + getContextIdentifier()
                + "\",\"" + "AuthenticatedUser" + "\" : \"" + getUserNameForAuthenticationStep()
                + "\",\"" + "AuthenticatedUserTenantDomain" + "\" : \"" + getTenantDomainForAuthenticationStep()
                + "\",\"" + "ServiceProviderName" + "\" : \"" + getServiceProvider()
                + "\",\"" + "RequestType" + "\" : \"" + getInboundProtocol()
                + "\",\"" + "RelyingParty" + "\" : \"" + getRelyingParty()
                + "\",\"" + "AuthenticatedIdP" + "\" : \"" + getIdentityProviderForAuthenticationStep()
                + "\"";

        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                getUserNameForAuthenticationStep(),
                "LoginStepSuccess",
                "ApplicationAuthenticationFramework", auditData, FrameworkConstants.AUDIT_SUCCESS));

    }

    protected void doPublishAuthenticationStepFailure() {

        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + getContextIdentifier()
                + "\",\"" + "ServiceProviderName" + "\" : \"" + getServiceProvider()
                + "\",\"" + "RequestType" + "\" : \"" + getInboundProtocol()
                + "\",\"" + "RelyingParty" + "\" : \"" + getRelyingParty()
                + "\",\"" + "StepNo" + "\" : \"" + getStepNoForAutheticationStep()
                + "\"";

        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                null,
                "Login",
                "ApplicationAuthenticationFramework", auditData, FrameworkConstants.AUDIT_FAILED));
    }

    protected void doPublishAuthenticationSuccess() {

        AuthenticationResult authenticationResult = new AuthenticationResult();
        authenticationResult.setAuthenticated(true);
        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + getContextIdentifier()
                + "\",\"" + "AuthenticatedUser" + "\" : \"" + getSubjectIdentifier()
                + "\",\"" + "AuthenticatedUserTenantDomain" + "\" : \"" + getTenantDomainForAuthentication()
                + "\",\"" + "ServiceProviderName" + "\" : \"" + getServiceProvider()
                + "\",\"" + "RequestType" + "\" : \"" + getInboundProtocol()
                + "\",\"" + "RelyingParty" + "\" : \"" + getRelyingParty()
                + "\",\"" + "AuthenticatedIdPs" + "\" : \"" + getIdenitityProviderList()
                + "\"";

        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                getSubjectIdentifier(),
                "Login",
                "ApplicationAuthenticationFramework", auditData, FrameworkConstants.AUDIT_SUCCESS));
    }

    protected void doPublishAuthenticationFailure() {

        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + getContextIdentifier()
                + "\",\"" + "ServiceProviderName" + "\" : \"" + getServiceProvider()
                + "\",\"" + "RequestType" + "\" : \"" + getInboundProtocol()
                + "\",\"" + "RelyingParty" + "\" : \"" + getRelyingParty()
                + "\",\"" + "StepNo" + "\" : \"" + getStepNoForAuthentication()
                + "\"";

        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                null,
                "Login",
                "ApplicationAuthenticationFramework", auditData, FrameworkConstants.AUDIT_FAILED));
    }

    protected void publishSessionTermination() {

        if (context == null) {
            return;
        }
        SequenceConfig sequenceConfig = this.context.getSequenceConfig();
        AuthenticatedUser authenticatedUser = null;
        String username = "";
        String tenantDomain = "";
        String authenticatedIDPs = "";

        if (sequenceConfig != null && sequenceConfig.getAuthenticatedUser() != null) {
            authenticatedUser = sequenceConfig.getAuthenticatedUser();
            authenticatedIDPs = sequenceConfig.getAuthenticatedIdPs();
        } else {
            Object authenticatedUserObj = this.sessionContext.getProperty(FrameworkConstants.AUTHENTICATED_USER);
            if (authenticatedUserObj != null) {
                authenticatedUser = (AuthenticatedUser) authenticatedUserObj;
            }
        }

        if (authenticatedUser != null) {
            username = authenticatedUser.getAuthenticatedSubjectIdentifier();
            tenantDomain = authenticatedUser.getTenantDomain();
        }

        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + this.getContextIdentifier()
                + "\",\"" + "LoggedOutUser" + "\" : \"" + username
                + "\",\"" + "LoggedOutUserTenantDomain" + "\" : \"" + tenantDomain
                + "\",\"" + "ServiceProviderName" + "\" : \"" + this.getServiceProvider()
                + "\",\"" + "RequestType" + "\" : \"" + this.getInboundProtocol()
                + "\",\"" + "RelyingParty" + "\" : \"" + this.getRelyingParty()
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
