/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.data.publisher.application.authentication.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationDataPublisher;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthnDataPublisherProxy;
import org.wso2.carbon.identity.event.services.IdentityEventService;

@Component(
        name = "identity.data.publisher.authn",
        immediate = true
)
public class AuthenticationDataPublisherServiceComponent {

    private static Log log = LogFactory.getLog(AuthenticationDataPublisherServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleContext = context.getBundleContext();
            bundleContext
                    .registerService(AuthenticationDataPublisher.class.getName(), new AuthnDataPublisherProxy(), null);
            if (log.isDebugEnabled()) {
                log.debug("org.wso2.carbon.identity.data.publisher.application.authentication bundle is activated");
            }
        } catch (Exception e) {
            log.error("Error while activating org.wso2.carbon.identity.data.publisher.application.authentication bundle", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("org.wso2.carbon.identity.data.publisher.application.authentication bundle is deactivated");
        }
    }

    @Reference(
            name = "IdentityEventService",
            service = IdentityEventService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityEventService"
    )
    protected void setIdentityEventService(IdentityEventService eventService) {

        AuthenticationDataPublisherDataHolder.getInstance().setIdentityEventService(eventService);
    }

    protected void unsetIdentityEventService(IdentityEventService eventService) {

        AuthenticationDataPublisherDataHolder.getInstance().setIdentityEventService(null);
    }

}
