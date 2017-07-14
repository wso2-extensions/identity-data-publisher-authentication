/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.data.publisher.application.authentication;

import org.apache.axiom.om.util.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.idp.mgt.util.IdPManagementUtil;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class AuthnDataPublisherUtils {

    public static final Log LOG = LogFactory.getLog(AuthnDataPublisherUtils.class);
    private static final String APPLICATION_DOMAIN = "Application";
    private static final String WORKFLOW_DOMAIN = "Workflow";
    private static final String INTERNAL_EVERYONE_ROLE = "Internal/everyone";

    /**
     * Add default values if the values coming in are null or empty
     *
     * @param name  Name of the property configured in identity.xml
     * @param value In coming value
     * @return
     */
    public static String replaceIfNotAvailable(String name, String value) {
        if (StringUtils.isNotEmpty(name) && StringUtils.isEmpty(value)) {
            String defaultValue = IdentityUtil.getProperty(name);
            if (defaultValue != null) {
                return defaultValue;
            }
        }
        if (StringUtils.isEmpty(value)) {
            return AuthPublisherConstants.NOT_AVAILABLE;
        }
        return value;
    }

    /**
     * Get the expiration time of the session
     *
     * @param createdTime  Created time of the session
     * @param updatedTime  Updated time of the session
     * @param tenantDomain Tenant Domain
     * @param isRememberMe Whether remember me is enabled
     * @return Session expiration time
     */
    public static long getSessionExpirationTime(long createdTime, long updatedTime, String tenantDomain,
                                                boolean isRememberMe) {
        // If remember me is enabled, Session termination time will be fixed
        if (isRememberMe) {
            long rememberMeTimeout = TimeUnit.SECONDS.toMillis(IdPManagementUtil.getRememberMeTimeout(tenantDomain));
            return createdTime + rememberMeTimeout;
        }
        long idleSessionTimeOut = TimeUnit.SECONDS.toMillis(IdPManagementUtil.getIdleSessionTimeOut(tenantDomain));
        return idleSessionTimeOut + updatedTime;
    }

    /**
     * Hash given string using sha-256
     *
     * @param value string to be hashed
     * @return Hashed string using sha-256
     * @throws NoSuchAlgorithmException
     */
    public static String hashString(String value) throws NoSuchAlgorithmException {
        MessageDigest dgst = MessageDigest.getInstance(AuthPublisherConstants.SHA_256);
        byte[] byteValue = dgst.digest(value.getBytes());
        value = Base64.encode(byteValue);
        return value;
    }

    /**
     * Get metadata array for different tenants with tenant domain
     * @param tenantDomain
     * @return
     */
    public static Object[] getMetaDataArray(String tenantDomain) {
        Object[] metaData = new Object[1];
        if (StringUtils.isBlank(tenantDomain)) {
            metaData[0] = MultitenantConstants.SUPER_TENANT_ID;
        } else {
            metaData[0] = IdentityTenantUtil.getTenantId(tenantDomain);
        }
        return metaData;
    }

    public static String[] getTenantDomains(String spTenantDomain, String userTenantDomain) {

        if (StringUtils.isBlank(userTenantDomain) || userTenantDomain.equalsIgnoreCase(AuthPublisherConstants
                .NOT_AVAILABLE)) {
            return new String[]{spTenantDomain};
        }
        if (StringUtils.isBlank(spTenantDomain) || userTenantDomain.equalsIgnoreCase(AuthPublisherConstants
                .NOT_AVAILABLE)) {
            return new String[]{userTenantDomain};
        }
        if (spTenantDomain.equalsIgnoreCase(userTenantDomain)) {
            return new String[]{userTenantDomain};
        } else {
            return new String[]{userTenantDomain, spTenantDomain};
        }
    }

    /**
     * Filter roles so that they don't have Internal roles except Internal/Everyone and all application roles
     *
     * @param roleList All roles
     * @return All external roles and Internal roles except internal everyone and application roles.
     */
    public static List<String> filterRoles(String[] roleList) {
        List<String> externalRoles = new ArrayList<String>();
        if (roleList != null) {
            int index;
            for (String role : roleList) {
                if (StringUtils.isNotBlank(role)) {
                    index = role.indexOf(CarbonConstants.DOMAIN_SEPARATOR);
                    if (index > 0) {
                        String domain = role.substring(0, index);
                        if (UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(domain)
                                && INTERNAL_EVERYONE_ROLE.equalsIgnoreCase(role.trim())) {
                                continue;
                        } else if (APPLICATION_DOMAIN.equalsIgnoreCase(domain)
                                || WORKFLOW_DOMAIN.equalsIgnoreCase(domain)) {
                            continue;
                        }
                    }
                    externalRoles.add(UserCoreUtil.removeDomainFromName(role));
                }
            }
        }
        return externalRoles;
    }

    /**
     * Returns the IDP name of IDP which is used to get the subject identifier.
     *
     * @param context Authentication context.
     * @return Name of the identity provider.
     */
    public static String getSubjectStepIDP(AuthenticationContext context) {
        SequenceConfig sequenceConfig = context.getSequenceConfig();
        for (Map.Entry<Integer, StepConfig> entry : sequenceConfig.getStepMap().entrySet()) {
            StepConfig stepConfig = entry.getValue();
            if (stepConfig.isSubjectIdentifierStep() && StringUtils.isNotEmpty(stepConfig.getAuthenticatedIdP())) {
                return stepConfig.getAuthenticatedIdP();
            }
        }
        return AuthPublisherConstants.NOT_AVAILABLE;
    }
}
