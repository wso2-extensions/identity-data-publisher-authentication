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
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.idp.mgt.util.IdPManagementUtil;

import javax.servlet.http.HttpServletRequest;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

public class AuthnDataPublisherUtils {

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

}
