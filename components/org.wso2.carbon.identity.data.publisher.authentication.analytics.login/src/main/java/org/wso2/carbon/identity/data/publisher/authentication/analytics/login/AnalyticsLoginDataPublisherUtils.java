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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;

import java.util.Map;

/*
 * TODO - comment class work
 */
public class AnalyticsLoginDataPublisherUtils {

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
        return AnalyticsLoginDataPublishConstants.NOT_AVAILABLE;
    }
}
