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

import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.event.IdentityEventConstants;

import java.util.Map;

/*
 * Utiltities for authentication audit logger
 */
public class AuthenticationAuditLoggerUtils {

    public static AuthenticationContext getAuthenticationContextFromProperties(Map<String, Object> properties) {

        return (AuthenticationContext) properties.get(IdentityEventConstants.EventProperty.CONTEXT);
    }

    public static AuthenticatorStatus getAutheticatorStatusFromProperties(Map<String, Object> properties) {

        return (AuthenticatorStatus) properties.get(IdentityEventConstants.EventProperty.AUTHENTICATION_STATUS);
    }

    public static SessionContext getSessionContextFromProperties(Map<String, Object> properties) {

        return (SessionContext) properties.get(IdentityEventConstants.EventProperty.SESSION_CONTEXT);
    }


    public static Map<String, Object> getParamsFromProperties(Map<String, Object> properties) {

        return (Map<String, Object>) properties.get(IdentityEventConstants.EventProperty.PARAMS);
    }

    public static boolean hasPreviousLocalEvent(AuthenticationContext context) {

        Map<String, AuthenticatedIdPData> previousAuthenticatedIDPs = context.getPreviousAuthenticatedIdPs();
        if (previousAuthenticatedIDPs.get(FrameworkConstants.LOCAL_IDP_NAME) != null) {
            return true;
        }
        return false;
    }

    public static boolean convertToBoolean(Object object) {

        if (object != null) {
            return (Boolean) object;
        }
        return false;
    }

    public static int getLocalStepNo(AuthenticationContext context) {

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

}
