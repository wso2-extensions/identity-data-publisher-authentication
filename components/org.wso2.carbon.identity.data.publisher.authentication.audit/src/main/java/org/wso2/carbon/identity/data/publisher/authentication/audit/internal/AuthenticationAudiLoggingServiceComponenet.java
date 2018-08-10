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

package org.wso2.carbon.identity.data.publisher.authentication.audit.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.data.publisher.authentication.audit.AuthenticationAuditLogingHandler;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;

/*
 * Service Component for authentication audit logger
 */

@Component(
        name = "identity.data.publisher.authentication.audit",
        immediate = true
)
public class AuthenticationAudiLoggingServiceComponenet {

    private static Log log = LogFactory.getLog(AuthenticationAudiLoggingServiceComponenet.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleContext = context.getBundleContext();
            bundleContext.registerService(AbstractEventHandler.class,
                    new AuthenticationAuditLogingHandler(), null);

            if (log.isDebugEnabled()) {
                log.debug("org.wso2.carbon.identity.data.publisher.authentication.audit" +
                        " bundle is activated");
            }
        } catch (Exception e) {
            log.error("Error while activating org.wso2.carbon.identity.data.publisher.authentication" +
                    ".audit", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("org.wso2.carbon.identity.data.publisher.authentication.audit bundle is deactivated");
        }
    }

}
