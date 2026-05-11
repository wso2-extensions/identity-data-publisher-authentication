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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthPublisherConstants;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthnDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.login.internal.AnalyticsLoginDataPublishDataHolder;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.login.model.AuthenticationData;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementServerException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.io.Serializable;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.data.publisher.authentication.analytics.login.AnalyticsLoginDataPublishConstants.IS_INVALID_USERNAME;
import static org.wso2.carbon.identity.data.publisher.authentication.analytics.login.AnalyticsLoginDataPublishConstants.USERNAME_USER_INPUT;

/**
 * Utils for Analytics Login data publisher.
 */
public class AnalyticsLoginDataPublisherUtils {

    private static final Log LOG = LogFactory.getLog(AnalyticsLoginDataPublisherUtils.class);

    private static final String APPLICATION_DOMAIN = "Application";
    private static final String WORKFLOW_DOMAIN = "Workflow";
    private static final String INTERNAL_EVERYONE_ROLE = "Internal/everyone";
    public static final String ORGANIZATION_AUTHENTICATOR = "OrganizationAuthenticator";
    public static final String ORG_ID = "orgId";
    public static final String IS_FRAGMENT_APP = "isFragmentApp";

    /**
     * Build authentication data object for authentication step from event.
     *
     * @param event Event.
     * @return Authentication data object
     */
    public static AuthenticationData buildAuthnDataForAuthnStep(Event event) {

        return buildAuthnDataForAuthnStep(event, false);
    }

    /**
     * Build authentication data object for authentication step from event.
     *
     * @param event                      Event.
     * @param resolvePrimaryTenantDomain if {@code true}, SP and user tenant domains are resolved
     *                                   to the primary organisation's org-handle before publishing.
     * @return Authentication data object
     */
    public static AuthenticationData buildAuthnDataForAuthnStep(Event event, boolean resolvePrimaryTenantDomain) {

        Map<String, Object> properties = event.getEventProperties();
        HttpServletRequest request = (HttpServletRequest) properties.get(IdentityEventConstants.EventProperty.REQUEST);
        Map<String, Object> params = (Map<String, Object>) properties.get(IdentityEventConstants.EventProperty.PARAMS);
        AuthenticationContext context = (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.
                CONTEXT);
        AuthenticatorStatus status = (AuthenticatorStatus) properties.get(IdentityEventConstants.EventProperty.
                AUTHENTICATION_STATUS);

        // Tenant cache: avoids redundant DB lookups for the same domain within this call.
        Map<String, Tenant> tenantCache = new HashMap<>();

        AuthenticationData authenticationData = new AuthenticationData();
        setIdpForAuthnStep(context, authenticationData);
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        boolean isInvalidUsername =
                context.getProperty(IS_INVALID_USERNAME) != null && (boolean) context.getProperty(IS_INVALID_USERNAME);
        context.setProperty(IS_INVALID_USERNAME, null);
        setUserDataForAuthnStep(authenticationData, userObj, isInvalidUsername, context, tenantCache);

        Object isFederatedObj = params.get(FrameworkConstants.AnalyticsAttributes.IS_FEDERATED);
        setIdpTypeForAuthnStep(authenticationData, isFederatedObj);

        authenticationData.setContextId(context.getContextIdentifier());
        authenticationData.setEventId(UUID.randomUUID().toString());
        authenticationData.setEventType(AnalyticsLoginDataPublishConstants.STEP_EVENT);
        authenticationData.setAuthnSuccess(false);
        if (request != null) {
            authenticationData.setRemoteIp(IdentityUtil.getClientIpAddress(request));
        } else {
            authenticationData.setRemoteIp((String) params.get(AuthPublisherConstants.REMOTE_IP_ADDRESS));
        }
        authenticationData.setServiceProvider(context.getServiceProviderName());
        authenticationData.setInboundProtocol(context.getRequestType());
        authenticationData.setRememberMe(context.isRememberMe());
        authenticationData.setForcedAuthn(context.isForceAuthenticate());
        authenticationData.setPassive(context.isPassiveAuthenticate());
        authenticationData.setInitialLogin(false);
        authenticationData.setAuthenticator(context.getCurrentAuthenticator());
        authenticationData.setSuccess(AuthenticatorStatus.PASS == status);
        authenticationData.setStepNo(context.getCurrentStep());
        authenticationData.setUsernameUserInput((String) context.getProperty(USERNAME_USER_INPUT));
        setTenantDataForIdpStep(context, status, authenticationData, resolvePrimaryTenantDomain);
        updateSpResidingData(context, authenticationData, tenantCache);

        authenticationData.addParameter(AuthPublisherConstants.RELYING_PARTY, context.getRelyingParty());
        return authenticationData;
    }

    /**
     * Build authentication data object for authentication step from event.
     * This method is for new stream definition.
     *
     * @param event
     * @return Authentication data object
     */
    public static AuthenticationData buildAuthnDataForAuthnStepV110(Event event) {

        return buildAuthnDataForAuthnStepV110(event, false);
    }

    /**
     * Build authentication data object for authentication step from event.
     * This method is for new stream definition.
     *
     * @param event                      Event.
     * @param resolvePrimaryTenantDomain if {@code true}, SP and user tenant domains are resolved
     *                                   to the primary organisation's org-handle before publishing.
     * @return Authentication data object
     */
    public static AuthenticationData buildAuthnDataForAuthnStepV110(Event event, boolean resolvePrimaryTenantDomain) {

        AuthenticationData authenticationData = buildAuthnDataForAuthnStep(event, resolvePrimaryTenantDomain);
        Map<String, Object> properties = event.getEventProperties();
        AuthenticationContext context = (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.
                CONTEXT);
        authenticationData.setDuration(AnalyticsLoginDataPublisherUtils.replaceIfLongNotAvailable(
                context.getAnalyticsData(FrameworkConstants.AnalyticsData.CURRENT_AUTHENTICATOR_DURATION)));
        authenticationData.setErrorCode(AnalyticsLoginDataPublisherUtils.replaceIfStringNotAvailable(
                context.getAnalyticsData(FrameworkConstants.AnalyticsData.CURRENT_AUTHENTICATOR_ERROR_CODE)));
        authenticationData.setCustomParams(getCustomParam(context));
        return authenticationData;
    }

    private static void setTenantDataForIdpStep(AuthenticationContext context, AuthenticatorStatus status,
                                                AuthenticationData authenticationData,
                                                boolean resolvePrimaryTenantDomain) {

        String spTenantDomain = context.getTenantDomain();
        String userTenantDomain = authenticationData.getTenantDomain();

        if (resolvePrimaryTenantDomain) {
            // Resolve SP domain first; reuse the result for user domain when both are identical
            // (most common case) to avoid a second call.
            String resolvedSpTenantDomain = StringUtils.isNotBlank(spTenantDomain)
                    ? getPrimaryOrgTenantDomain(spTenantDomain) : spTenantDomain;
            String resolvedUserTenantDomain;
            if (StringUtils.isNotBlank(userTenantDomain)) {
                resolvedUserTenantDomain = userTenantDomain.equals(spTenantDomain)
                        ? resolvedSpTenantDomain
                        : getPrimaryOrgTenantDomain(userTenantDomain);
            } else {
                resolvedUserTenantDomain = userTenantDomain;
            }
            spTenantDomain = resolvedSpTenantDomain;
            userTenantDomain = resolvedUserTenantDomain;
        }

        if (AuthenticatorStatus.PASS == status) {
            authenticationData.addParameter(AnalyticsLoginDataPublishConstants.TENANT_DOMAIN_NAMES,
                    AuthnDataPublisherUtils.getTenantDomains(spTenantDomain, userTenantDomain));
        } else {
            // Should publish the event to both SP tenant domain and the tenant domain of the user who did
            // the login attempt.
            if (context.getSequenceConfig() != null && context.getSequenceConfig().getApplicationConfig() != null
                    && context.getSequenceConfig().getApplicationConfig().isSaaSApp()) {
                authenticationData.addParameter(AnalyticsLoginDataPublishConstants.TENANT_DOMAIN_NAMES,
                        AuthnDataPublisherUtils.getTenantDomains(spTenantDomain, userTenantDomain));
            } else {
                authenticationData.addParameter(AnalyticsLoginDataPublishConstants.TENANT_DOMAIN_NAMES,
                        AuthnDataPublisherUtils.getTenantDomains(spTenantDomain, null));
            }
        }
    }

    /**
     * Resolves the primary organisation's tenant domain (org-handle) for the given tenant domain.
     * Delegates to {@link OrganizationManagementUtil#getRootOrgTenantDomainBySubOrgTenantDomain},
     * which handles both root and sub-org tenants correctly.
     * Falls back to returning {@code tenantDomain} unchanged on any error.
     */
    private static String getPrimaryOrgTenantDomain(String tenantDomain) {

        try {
            if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                return tenantDomain;
            }

            return OrganizationManagementUtil.getRootOrgTenantDomainBySubOrgTenantDomain(tenantDomain);
        } catch (OrganizationManagementException e) {
            LOG.warn("Failed to resolve primary org handle for domain: " + tenantDomain
                    + ". Falling back to original domain.", e);
            return tenantDomain;
        }
    }

    /**
     * Loads a {@link Tenant} by domain, consulting {@code tenantCache} first so the same tenant
     * is never fetched more than once per request.
     */
    private static Tenant loadTenantByDomain(String domain, Map<String, Tenant> tenantCache)
            throws UserStoreException {

        if (tenantCache.containsKey(domain)) {
            return tenantCache.get(domain);
        }
        Tenant tenant = AnalyticsLoginDataPublishDataHolder.getInstance()
                .getRealmService().getTenantManager().getTenantByDomain(domain);
        // Cache even a null result so we don't hit the DB again for the same domain.
        tenantCache.put(domain, tenant);
        return tenant;
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

    private static void setUserDataForAuthnStep(AuthenticationData authenticationData, Object userObj,
                                                boolean isInvalidUsername, AuthenticationContext context,
                                                Map<String, Tenant> tenantCache) {

        if (userObj instanceof User) {
            User user = (User) userObj;
            authenticationData.setTenantDomain(user.getTenantDomain());
            authenticationData.setUserStoreDomain(user.getUserStoreDomain());
            if (!isInvalidUsername) {
                authenticationData.setUsername(user.getUserName());
            }
        }
        if (userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            if (StringUtils.isEmpty(user.getUserName())) {
                authenticationData.setUsername(user.getAuthenticatedSubjectIdentifier());
            }
            try {
                authenticationData.setUserId(user.getUserId());
            } catch (UserIdNotFoundException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Null user id is found in the AuthenticatedUser instance.");
                }
            }
            updateUserOrgData(authenticationData, context, user, (User) userObj, tenantCache);
        } else {
            try {
                // Resolve userId and organization data for unauthenticated users.
                if (userObj instanceof User) {
                    User user = (User) userObj;
                    RealmService realmService = AnalyticsLoginDataPublishDataHolder.getInstance().getRealmService();
                    AbstractUserStoreManager userStoreManager =
                            (AbstractUserStoreManager) realmService.getTenantUserRealm(
                                    IdentityTenantUtil.getTenantId(user.getTenantDomain())).getUserStoreManager();
                    org.wso2.carbon.user.core.common.User user1 = userStoreManager.getUser(null,
                            UserCoreUtil.addDomainToName(user.getUserName(), user.getUserStoreDomain()));
                    authenticationData.setUserId(user1.getUserID());
                    updateUserOrgData(authenticationData, context, null, (User) userObj, tenantCache);
                }
            } catch (UserStoreException e) {
                throw new RuntimeException(e);
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
     * @param event  Event
     * @return AuthenticationData - authentication data object
     */
    public static AuthenticationData buildAuthnDataForAuthentication(Event event) {

        return buildAuthnDataForAuthentication(event, false);
    }

    /**
     * Build authentication data object for authentication from event.
     *
     * @param event                      Event
     * @param resolvePrimaryTenantDomain if {@code true}, SP and user tenant domains are resolved
     *                                   to the primary organisation's org-handle before publishing.
     * @return AuthenticationData - authentication data object
     */
    public static AuthenticationData buildAuthnDataForAuthentication(Event event, boolean resolvePrimaryTenantDomain) {

        Map<String, Object> properties = event.getEventProperties();
        HttpServletRequest request = (HttpServletRequest) properties.get(IdentityEventConstants.EventProperty.REQUEST);
        Map<String, Object> params = (Map<String, Object>) properties.get(IdentityEventConstants.EventProperty.PARAMS);
        AuthenticationContext context = (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.
                CONTEXT);
        AuthenticatorStatus status = (AuthenticatorStatus) properties.get(IdentityEventConstants.EventProperty.
                AUTHENTICATION_STATUS);

        // Tenant cache: avoids redundant DB lookups for the same domain within this call.
        Map<String, Tenant> tenantCache = new HashMap<>();

        AuthenticationData authenticationData = new AuthenticationData();
        Object userObj = params.get(FrameworkConstants.AnalyticsAttributes.USER);
        setUserDataForAuthentication(authenticationData, userObj, context, tenantCache);

        authenticationData = setIdpDataAndStepForAuthentication(context, status, authenticationData);

        authenticationData.setEventType(AnalyticsLoginDataPublishConstants.OVERALL_EVENT);
        authenticationData.setContextId(context.getContextIdentifier());
        authenticationData.setEventId(UUID.randomUUID().toString());
        if (AuthenticatorStatus.PASS.equals(status)) {
            authenticationData.setAuthnSuccess(true);
        } else if (AuthenticatorStatus.FAIL.equals(status)) {
            authenticationData.setAuthnSuccess(false);
        }
        if (request != null) {
            authenticationData.setRemoteIp(IdentityUtil.getClientIpAddress(request));
        } else {
            authenticationData.setRemoteIp((String) params.get(AuthPublisherConstants.REMOTE_IP_ADDRESS));
        }
        authenticationData.setServiceProvider(context.getServiceProviderName());
        authenticationData.setInboundProtocol(context.getRequestType());
        authenticationData.setRememberMe(context.isRememberMe());
        authenticationData.setForcedAuthn(context.isForceAuthenticate());
        authenticationData.setPassive(context.isPassiveAuthenticate());
        authenticationData.setUsernameUserInput((String) context.getProperty(USERNAME_USER_INPUT));
        setTenantDataForAuthentication(context, status, authenticationData, resolvePrimaryTenantDomain);
        updateSpResidingData(context, authenticationData, tenantCache);

        authenticationData.addParameter(AuthPublisherConstants.RELYING_PARTY, context.getRelyingParty());
        setIdPAndAuthenticatorData(context, authenticationData);

        return authenticationData;
    }

    private static void setIdPAndAuthenticatorData(AuthenticationContext authContext,
                                                          AuthenticationData authenticationData) {

        Map<String, AuthenticatedIdPData> authenticatedIdPs = authContext.getCurrentAuthenticatedIdPs();
        if (MapUtils.isEmpty(authenticatedIdPs)) {
            return;
        }
        String serviceProvider = authContext.getServiceProviderName();
        List<String> idpIdList = new ArrayList<>();
        List authenticatorList = new ArrayList<>();
        authenticatedIdPs.values().forEach(authenticatedIdPData -> {
            addIdPResourceId(authenticatedIdPData, idpIdList, authContext.getTenantDomain(), serviceProvider);
            authenticatorList.add(authenticatedIdPData.getAuthenticators().stream()
                    .map(AuthenticatorConfig::getName).collect(Collectors.toList()));
        });
        List<String> flattenedAuthenticatorList = new ArrayList<>();
        for (List<String> authenticators : (List<List<String>>) authenticatorList) {
            for (Object authenticator : authenticators) {
                flattenedAuthenticatorList.add(authenticator.toString().replaceAll("[\\[\\]]", ""));
            }
        }
        if (!idpIdList.isEmpty()) {
            authenticationData.setIdps(idpIdList);
        }
        if (!authenticatorList.isEmpty()) {
            authenticationData.setAuthenticators(flattenedAuthenticatorList);
        }
    }

    /**
     * Set the IdP ID data to the Authentication IdP list.
     * @param authenticatedIdPData  Authenticated IdP data.
     * @param idpIdList             IdP ID list.
     * @param tenantDomain          Tenant domain.
     */
    private static void addIdPResourceId(AuthenticatedIdPData authenticatedIdPData, List<String> idpIdList,
                                  String tenantDomain, String serviceProvider) {

        String key = authenticatedIdPData.getIdpName();
        String resourceId = null;
        if (authenticatedIdPData != null && authenticatedIdPData.getAuthenticators() != null &&
                !authenticatedIdPData.getAuthenticators().isEmpty()) {
            for (AuthenticatorConfig config : authenticatedIdPData.getAuthenticators()) {
                if (config.getIdps().containsKey(key) && config.getIdps().get(key).getResourceId() != null) {
                    resourceId = config.getIdps().get(key).getResourceId();
                    break;
                }
            }
        }
        // If the resource ID is not found in the authenticator config, fetch from the database.
        if (resourceId == null) {
            resourceId = getIdPResourceIdByName(key, tenantDomain);
        }
        if (resourceId != null && !idpIdList.contains(resourceId)) {
            idpIdList.add(resourceId);
        }
        if (resourceId == null) {
            LOG.warn("Unable to resolve authenticated IdP resource Id for tenant: " + tenantDomain + " and IdP: " +
                    key + " and service provider: " + serviceProvider);
        }
    }

    /**
     * Get the IdP ID by name.
     *
     * @param idpName       IdP name.
     * @param tenantDomain  Tenant domain.
     * @return IdP ID.
     */
    private static String getIdPResourceIdByName(String idpName, String tenantDomain) {

        String resourceId = null;
        try {
            IdentityProvider identityProvider = IdentityProviderManager.getInstance().getIdPByName(idpName,
                    tenantDomain);
            if (identityProvider != null) {
                resourceId = identityProvider.getResourceId();
            }
        } catch (IdentityProviderManagementException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error while retrieving Identity Provider for name: " + idpName + " and tenant: " +
                        tenantDomain, e);
            }
        }
        return resourceId;
    }

    /**
     * Build authentication data object for authentication from event.
     * This method is for new stream definition V110.
     *
     * @param event  Event
     * @return AuthenticationData - authentication data object
     */
    public static AuthenticationData buildAuthnDataForAuthenticationV110(Event event) {

        return buildAuthnDataForAuthenticationV110(event, false);
    }

    /**
     * Build authentication data object for authentication from event.
     * This method is for new stream definition V110.
     *
     * @param event                      Event
     * @param resolvePrimaryTenantDomain if {@code true}, SP and user tenant domains are resolved
     *                                   to the primary organisation's org-handle before publishing.
     * @return AuthenticationData - authentication data object
     */
    public static AuthenticationData buildAuthnDataForAuthenticationV110(Event event,
                                                                         boolean resolvePrimaryTenantDomain) {

        AuthenticationData authenticationData = buildAuthnDataForAuthentication(event, resolvePrimaryTenantDomain);
        Map<String, Object> properties = event.getEventProperties();
        AuthenticationContext context = (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.
                CONTEXT);
        authenticationData.setDuration(AnalyticsLoginDataPublisherUtils.replaceIfLongNotAvailable(
                context.getAnalyticsData(FrameworkConstants.AnalyticsData.AUTHENTICATION_DURATION)));
        authenticationData.setErrorCode(AnalyticsLoginDataPublisherUtils.replaceIfStringNotAvailable(
                context.getAnalyticsData(FrameworkConstants.AnalyticsData.AUTHENTICATION_ERROR_CODE)));
        authenticationData.setCustomParams(getCustomParam(context));
        return authenticationData;
    }

    private static void setTenantDataForAuthentication(AuthenticationContext context, AuthenticatorStatus status,
                                                       AuthenticationData authenticationData,
                                                       boolean resolvePrimaryTenantDomain) {

        String spTenantDomain = context.getTenantDomain();
        String userTenantDomain = authenticationData.getTenantDomain();

        if (resolvePrimaryTenantDomain) {
            // Resolve SP domain first; reuse the result for user domain when both are identical
            // (most common case) to avoid a second call.
            String resolvedSp = StringUtils.isNotBlank(spTenantDomain)
                    ? getPrimaryOrgTenantDomain(spTenantDomain) : spTenantDomain;
            String resolvedUser;
            if (StringUtils.isNotBlank(userTenantDomain)) {
                resolvedUser = userTenantDomain.equals(spTenantDomain)
                        ? resolvedSp
                        : getPrimaryOrgTenantDomain(userTenantDomain);
            } else {
                resolvedUser = userTenantDomain;
            }
            spTenantDomain = resolvedSp;
            userTenantDomain = resolvedUser;

        }

        if (status == AuthenticatorStatus.PASS) {
            authenticationData.addParameter(AnalyticsLoginDataPublishConstants.TENANT_DOMAIN_NAMES,
                    AuthnDataPublisherUtils.getTenantDomains(spTenantDomain, userTenantDomain));
            authenticationData.addParameter(AuthPublisherConstants.SUBJECT_IDENTIFIER,
                    context.getSequenceConfig().getAuthenticatedUser().getAuthenticatedSubjectIdentifier());
            authenticationData.addParameter(AuthPublisherConstants.AUTHENTICATED_IDPS,
                    context.getSequenceConfig().getAuthenticatedIdPs());
        } else {
            // Should publish the event to both SP tenant domain and the tenant domain of the user who did the login
            // attempt.
            if (context.getSequenceConfig() != null && context.getSequenceConfig().getApplicationConfig() != null
                    && context.getSequenceConfig().getApplicationConfig().isSaaSApp()) {
                authenticationData.addParameter(AnalyticsLoginDataPublishConstants.TENANT_DOMAIN_NAMES,
                        AuthnDataPublisherUtils.getTenantDomains(spTenantDomain, userTenantDomain));
            } else {
                authenticationData.addParameter(AnalyticsLoginDataPublishConstants.TENANT_DOMAIN_NAMES,
                        AuthnDataPublisherUtils.getTenantDomains(spTenantDomain, null));
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
                                                     Object userObj, AuthenticationContext context,
                                                     Map<String, Tenant> tenantCache) {

        if (userObj instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) userObj;
            authenticationData.setUsername(user.getUserName());
            try {
                authenticationData.setUserId(user.getUserId());
            } catch (UserIdNotFoundException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Null user id is found in the AuthenticatedUser instance.");
                }
            }
            authenticationData.setTenantDomain(user.getTenantDomain());
            authenticationData.setUserStoreDomain(user.getUserStoreDomain());
            updateUserOrgData(authenticationData, context, user, (User) userObj, tenantCache);
        }
    }

    private static void updateUserOrgData(AuthenticationData authenticationData, AuthenticationContext context,
                                          AuthenticatedUser authenticatedUser, User user,
                                          Map<String, Tenant> tenantCache) {

        authenticationData.setOrganizationLogin(context.isOrgApplicationLogin());
        authenticationData.setSharedAppLogin(context.isSharedAppLogin());
        if (authenticatedUser != null && authenticatedUser.getUserResidentOrganization() != null) {
            authenticationData.setUserResidingOrgId(authenticatedUser.getUserResidentOrganization());
        } else {
            if (ORGANIZATION_AUTHENTICATOR.equals(context.getCurrentAuthenticator())) {
                authenticationData.setUserResidingOrgId((String) context.getProperty(ORG_ID));
                // Legacy SSO login flow.
                authenticationData.setSharedAppLogin(true);
            } else {
                authenticationData.setUserResidingOrgId(getOrgUuid(user.getTenantDomain(), tenantCache).orElse(null));
            }
        }
        authenticationData.setUserLoginOrgId(getOrgUuid(user.getTenantDomain(), tenantCache).orElse(null));
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

    private static List<String> getCustomParam(AuthenticationContext context) {

        List<String> customParams = new ArrayList<>();
        for (int i = 0; i < FrameworkConstants.AnalyticsData.CUSTOM_PARAM_LENGTH; i++) {
            customParams.add(AnalyticsLoginDataPublisherUtils
                    .replaceIfStringNotAvailable(
                            context.getAnalyticsData(FrameworkConstants.AnalyticsData.CUSTOM_PARAM_PREFIX + i)));
        }
        return customParams;
    }

    /**
     * Add default values if the values coming in are null.
     *
     * @param serializable Authentication related param .
     * @return the object with type long.
     */
    public static long replaceIfLongNotAvailable(Serializable serializable) {

        if (serializable instanceof Long) {
            return (long) serializable;
        }
        return AnalyticsLoginDataPublishConstants.LONG_NOT_AVAILABLE;
    }

    /**
     * Add default values if the values coming in are null.
     *
     * @param serializable Authentication related param .
     * @return the object with type String.
     */
    public static String replaceIfStringNotAvailable(Serializable serializable) {

        if (serializable instanceof String) {
            return (String) serializable;
        }
        return AuthPublisherConstants.NOT_AVAILABLE;
    }

    public static Object replaceIfNotAvailable(Object object) {

        if (object != null) {
            return object;
        }
        return AuthPublisherConstants.NOT_AVAILABLE;
    }

    private static void updateSpResidingData(AuthenticationContext context, AuthenticationData authenticationData,
                                             Map<String, Tenant> tenantCache) {

        try {
            ServiceProvider sp = AnalyticsLoginDataPublishDataHolder.getInstance()
                    .getApplicationManagementService()
                    .getServiceProvider(context.getServiceProviderName(), context.getTenantDomain());
            if (sp == null || sp.getSpProperties() == null) {
                return;
            }
            Optional<ServiceProviderProperty> fragmentAppProperty = Arrays.stream(sp.getSpProperties())
                    .filter(s -> IS_FRAGMENT_APP.equals(s.getName()) && Boolean.parseBoolean(s.getValue()))
                    .findAny();
            String spResidingOrgId = null;

            Tenant tenant = loadTenantByDomain(context.getTenantDomain(), tenantCache);
            if (tenant != null) {
                if (fragmentAppProperty.isPresent()) {
                    spResidingOrgId = AnalyticsLoginDataPublishDataHolder.getInstance()
                            .getOrganizationManager()
                            .getPrimaryOrganizationId(tenant.getAssociatedOrganizationUUID());
                } else {
                    spResidingOrgId = tenant.getAssociatedOrganizationUUID();
                }
            }
            authenticationData.setServiceProviderResidingOrgId(spResidingOrgId);
        } catch (IdentityApplicationManagementException e) {
            LOG.error("Error while retrieving service provider for " + context.getServiceProviderName()
                    + " in tenant domain: " + context.getTenantDomain(), e);
        } catch (OrganizationManagementServerException e) {
            LOG.error("Error while retrieving primary organization ID for tenant: "
                    + context.getTenantDomain(), e);
        } catch (UserStoreException e) {
            LOG.error("Error while retrieving tenant information for domain: "
                    + context.getTenantDomain(), e);
        }
    }

    private static Optional<String> getOrgUuid(String tenantDomain, Map<String, Tenant> tenantCache) {

        try {
            if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                return Optional.of(OrganizationManagementConstants.SUPER_ORG_ID);
            }
            Tenant tenant = loadTenantByDomain(tenantDomain, tenantCache);
            return Optional.ofNullable(tenant.getAssociatedOrganizationUUID());
        } catch (UserStoreException e) {
            return Optional.empty();
        }
    }
}
