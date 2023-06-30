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
import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationDataPublisher;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.handler.MessageHandlerComparator;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthnDataPublisherProxy;
import org.wso2.carbon.identity.data.publisher.application.authentication.impl.AuthenticationAuditLogger;
import org.wso2.carbon.identity.data.publisher.application.authentication.impl.DASLoginDataPublisherImpl;
import org.wso2.carbon.identity.data.publisher.application.authentication.impl.DASSessionDataPublisherImpl;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Collections;

@Component(
        name = "identity.data.publisher.authn",
        immediate = true
)
public class AuthenticationDataPublisherServiceComponent {

    private static final Log log = LogFactory.getLog(AuthenticationDataPublisherServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleContext = context.getBundleContext();
            bundleContext
                    .registerService(AuthenticationDataPublisher.class.getName(), new DASLoginDataPublisherImpl(),
                            null);
            bundleContext
                    .registerService(AuthenticationDataPublisher.class.getName(), new DASSessionDataPublisherImpl(),
                            null);
            bundleContext
                    .registerService(AuthenticationDataPublisher.class.getName(), new AuthenticationAuditLogger(),
                            null);
            bundleContext
                    .registerService(AuthenticationDataPublisher.class.getName(), new AuthnDataPublisherProxy(),
                            null);
            if (log.isDebugEnabled()) {
                log.debug("org.wso2.carbon.identity.data.publisher.application.authentication bundle is activated");
            }
        } catch (Throwable e) {
            log.error("Error while activating org.wso2.carbon.identity.data.publisher.application.authentication " +
                    "bundle", e);
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

    @Reference(
            name = "EventStreamService",
            service = EventStreamService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetEventStreamService"
    )
    protected void setEventStreamService(EventStreamService eventStreamService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Event Stream Service");
        }
        AuthenticationDataPublisherDataHolder.getInstance().setPublisherService(eventStreamService);
    }

    protected void unsetEventStreamService(EventStreamService eventStreamService) {

        if (log.isDebugEnabled()) {
            log.debug("Un-setting the Event Stream Service");
        }
        AuthenticationDataPublisherDataHolder.getInstance().setPublisherService(null);
    }

    @Reference(
            name = "RealmService",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service.");
        }
        AuthenticationDataPublisherDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Un-setting the Realm Service.");
        }
        AuthenticationDataPublisherDataHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "AuthenticationDataPublisher",
            service = AuthenticationDataPublisher.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAuthenticationDataPublisher"
    )

    protected void setAuthenticationDataPublisher(AuthenticationDataPublisher publisher) {

        if (publisher != null && !FrameworkConstants.AnalyticsAttributes.AUTHN_DATA_PUBLISHER_PROXY.equalsIgnoreCase
                (publisher.getName())) {
            AuthenticationDataPublisherDataHolder.getInstance().getDataPublishers().add(publisher);
            Collections.sort(AuthenticationDataPublisherDataHolder.getInstance().getDataPublishers(),
                    new MessageHandlerComparator(null));
            Collections.reverse(AuthenticationDataPublisherDataHolder.getInstance().getDataPublishers());
        }
    }

    protected void unsetAuthenticationDataPublisher(AuthenticationDataPublisher publisher) {

        AuthenticationDataPublisherDataHolder.getInstance().getDataPublishers().remove(publisher);
    }
}
