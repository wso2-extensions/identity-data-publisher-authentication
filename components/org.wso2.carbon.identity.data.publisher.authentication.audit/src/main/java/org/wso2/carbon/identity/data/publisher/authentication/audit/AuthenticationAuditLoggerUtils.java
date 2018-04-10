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
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.data.publisher.authentication.audit.model.AuditDataObject;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/*
 * Utilities for Authentication Audit logger
 */
public class AuthenticationAuditLoggerUtils {
    public static final String NOT_AVAILABLE = "NOT_AVAILABLE";

    private static String getContextIdentifier(Map<String, Object> properties) {
        AuthenticationContext context = getAuthenticationContextFromProperties(properties);
        return context.getContextIdentifier();
    }

    private static String getUserName(Map<String, Object> properties) {
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

    private static String getTenantDomain(Map<String, Object> properties) {
        String tenantDomain = null;
        Map<String, Object> params = getParamsFromProperties(properties);
        AuthenticatorStatus status = (AuthenticatorStatus) properties.get(IdentityEventConstants.EventProperty.AUTHENTICATION_STATUS);
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        if (userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            if (status == AuthenticatorStatus.FAIL) {
                tenantDomain = user.getTenantDomain();
            }
        } else if (userObj instanceof User) {
            User user = (User) userObj;
            tenantDomain = user.getTenantDomain();
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

    private static String getIdentityProviderForAuthentication(Map<String, Object> properties) {
        AuthenticationContext context = getAuthenticationContextFromProperties(properties);
        return getSubjectStepIDP(context);

    }

    private static int getStepNo(Map<String, Object> properties) {
        AuthenticationContext context = getAuthenticationContextFromProperties(properties);
        return context.getCurrentStep();
    }

    private static Map<String, Object> getParamsFromProperties(Map<String, Object> properties) {
        return (Map<String, Object>) properties.get(IdentityEventConstants.EventProperty.PARAMS);
    }

    private static AuthenticationContext getAuthenticationContextFromProperties(Map<String, Object> properties) {
        return (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.CONTEXT);
    }

    private static String getSubjectStepIDP(AuthenticationContext context) {
        SequenceConfig sequenceConfig = context.getSequenceConfig();
        for (Map.Entry<Integer, StepConfig> entry : sequenceConfig.getStepMap().entrySet()) {
            StepConfig stepConfig = entry.getValue();
            if (stepConfig.isSubjectIdentifierStep() && StringUtils.isNotEmpty(stepConfig.getAuthenticatedIdP())) {
                return stepConfig.getAuthenticatedIdP();
            }
        }
        return AuthenticationAuditLoggerUtils.NOT_AVAILABLE;
    }

    public AuditDataObject createAuditDataObject(Event event) {
        Map<String, Object> properties = event.getEventProperties();
        HttpServletRequest request = (HttpServletRequest) properties.get(IdentityEventConstants.EventProperty.REQUEST);
        Map<String, Object> params = (Map<String, Object>) properties.get(IdentityEventConstants.EventProperty.PARAMS);
        AuthenticationContext context = (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.CONTEXT);
        AuthenticatorStatus status = (AuthenticatorStatus) properties.get(IdentityEventConstants.EventProperty.AUTHENTICATION_STATUS);


    }

}
