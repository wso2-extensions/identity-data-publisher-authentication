package org.wso2.carbon.identity.data.publisher.application.authentication.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.data.publisher.application.authentication.AbstractAuthenticationDataPublisher;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthPublisherConstants;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthnDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.application.authentication.model.AuthenticationData;
import org.wso2.carbon.identity.data.publisher.application.authentication.model.SessionData;

import java.security.NoSuchAlgorithmException;

public class AuthenticationAuditLogger extends AbstractAuthenticationDataPublisher {

    private static final Log AUDIT_LOG = CarbonConstants.AUDIT_LOG;
    public static final Log LOG = LogFactory.getLog(AuthenticationAuditLogger.class);


    @Override
    public String getName() {
        return "AuditDataPublisher";
    }

    @Override
    public int getPriority(MessageContext messageContext) {
        return 1;
    }

    @Override
    public void doPublishAuthenticationStepSuccess(AuthenticationData authenticationData) {

        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + authenticationData.getContextId()
                + "\",\"" + "AuthenticatedUser" + "\" : \"" + authenticationData.getUsername()
                + "\",\"" + "AuthenticatedUserTenantDomain" + "\" : \"" + authenticationData.getTenantDomain()
                + "\",\"" + "ServiceProviderName" + "\" : \"" + authenticationData.getServiceProvider()
                + "\",\"" + "RequestType" + "\" : \"" + authenticationData.getInboundProtocol()
                + "\",\"" + "RelyingParty" + "\" : \"" + authenticationData.getParameter(AuthPublisherConstants
                .RELYING_PARTY)
                + "\",\"" + "AuthenticatedIdP" + "\" : \"" + authenticationData.getIdentityProvider()
                + "\"";

        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                authenticationData.getUsername(),
                "LoginStepSuccess",
                "ApplicationAuthenticationFramework", auditData, FrameworkConstants.AUDIT_SUCCESS));


    }

    @Override
    public void doPublishAuthenticationStepFailure(AuthenticationData authenticationData) {

        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + authenticationData.getContextId()
                + "\",\"" + "ServiceProviderName" + "\" : \"" + authenticationData.getServiceProvider()
                + "\",\"" + "RequestType" + "\" : \"" + authenticationData.getInboundProtocol()
                + "\",\"" + "RelyingParty" + "\" : \"" + authenticationData.getParameter(AuthPublisherConstants
                .RELYING_PARTY)
                + "\",\"" + "StepNo" + "\" : \"" + authenticationData.getStepNo()
                + "\"";

        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                null,
                "Login",
                "ApplicationAuthenticationFramework", auditData, FrameworkConstants.AUDIT_FAILED));
    }

    @Override
    public void doPublishAuthenticationSuccess(AuthenticationData authenticationData) {

        AuthenticationResult authenticationResult = new AuthenticationResult();
        authenticationResult.setAuthenticated(true);
        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + authenticationData.getContextId()
                + "\",\"" + "AuthenticatedUser" + "\" : \"" + authenticationData.getParameter(AuthPublisherConstants
                .SUBJECT_IDENTIFIER)
                + "\",\"" + "AuthenticatedUserTenantDomain" + "\" : \"" + authenticationData.getTenantDomain()
                + "\",\"" + "ServiceProviderName" + "\" : \"" + authenticationData.getTenantDomain()
                + "\",\"" + "RequestType" + "\" : \"" + authenticationData.getInboundProtocol()
                + "\",\"" + "RelyingParty" + "\" : \"" + authenticationData.getParameter(AuthPublisherConstants
                .RELYING_PARTY)
                + "\",\"" + "AuthenticatedIdPs" + "\" : \"" + authenticationData.getParameter(AuthPublisherConstants
                .AUTHENTICATED_IDPS)
                + "\"";

        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                authenticationData.getParameter(AuthPublisherConstants.SUBJECT_IDENTIFIER),
                "Login",
                "ApplicationAuthenticationFramework", auditData, FrameworkConstants.AUDIT_SUCCESS));
    }

    @Override
    public void doPublishAuthenticationFailure(AuthenticationData authenticationData) {
        String auditData = "\"" + "ContextIdentifier" + "\" : \"" + authenticationData.getContextId()
                + "\",\"" + "ServiceProviderName" + "\" : \"" + authenticationData.getServiceProvider()
                + "\",\"" + "RequestType" + "\" : \"" + authenticationData.getInboundProtocol()
                + "\",\"" + "RelyingParty" + "\" : \"" + authenticationData.getParameter(AuthPublisherConstants
                .RELYING_PARTY)
                + "\",\"" + "StepNo" + "\" : \"" + authenticationData.getStepNo()
                + "\"";

        AUDIT_LOG.info(String.format(
                FrameworkConstants.AUDIT_MESSAGE,
                null,
                "Login",
                "ApplicationAuthenticationFramework", auditData, FrameworkConstants.AUDIT_FAILED));
    }

    @Override
    public void doPublishSessionCreation(SessionData sessionData) {
        // Nothing to implement
    }

    @Override
    public void doPublishSessionUpdate(SessionData sessionData) {
        // Nothing to implement
    }

    @Override
    public void doPublishSessionTermination(SessionData sessionData) {

        String auditData = null;
        try {
            auditData = "\"" + "ContextIdentifier" + "\" : \"" + AuthnDataPublisherUtils.hashString(sessionData.getSessionId())
                    + "\"";
            AUDIT_LOG.info(String.format(
                    FrameworkConstants.AUDIT_MESSAGE,
                    sessionData.getUser(),
                    "Logout",
                    "ApplicationAuthenticationFramework", auditData, FrameworkConstants.AUDIT_SUCCESS));
        } catch (NoSuchAlgorithmException e) {
            LOG.debug("Error while hashing common auth ID");
        }
    }

    @Override
    public boolean isEnabled(MessageContext messageContext) {
        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.readEventListenerProperty
                (AbstractIdentityMessageHandler.class.getName(), this.getClass().getName());

        if (identityEventListenerConfig == null) {
            return true;
        }

        return Boolean.parseBoolean(identityEventListenerConfig.getEnable());
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {
        return true;
    }
}
