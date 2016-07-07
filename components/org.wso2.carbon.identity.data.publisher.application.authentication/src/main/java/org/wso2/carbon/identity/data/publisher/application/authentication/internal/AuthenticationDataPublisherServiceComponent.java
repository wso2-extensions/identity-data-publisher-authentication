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

import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationDataPublisher;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.data.publisher.application.authentication.AuthnDataPublisherProxy;
import org.wso2.carbon.identity.data.publisher.application.authentication.impl.DASLoginDataPublisherImpl;
import org.wso2.carbon.identity.data.publisher.application.authentication.impl.DASSessionDataPublisherImpl;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="org.wso2.carbon.identity.data.publisher.authn" immediate="true"
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService"
 * cardinality="1..1" policy="dynamic" bind="setRegistryService"
 * unbind="unsetRegistryService"
 * @scr.reference name="realm.service" interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService"
 * unbind="unsetRealmService"
 * @scr.reference name="eventStreamManager.service"
 * interface="org.wso2.carbon.event.stream.core.EventStreamService" cardinality="1..1"
 * policy="dynamic" bind="setEventStreamService" unbind="unsetEventStreamService"
 * unbind="unsetEventStreamService"
 * @scr.reference name="identity.authentication.data.publisher"
 * interface="org.wso2.carbon.identity.application.authentication.framework.AuthenticationDataPublisher"
 * cardinality="0..n" policy="dynamic" bind="setAuthenticationDataPublisher"
 * unbind="unsetAuthenticationDataPublisher"
 */
public class AuthenticationDataPublisherServiceComponent {

    protected void activate(ComponentContext context) {

        BundleContext bundleContext = context.getBundleContext();
        bundleContext
                .registerService(AuthenticationDataPublisher.class.getName(), new DASLoginDataPublisherImpl(), null);
        bundleContext
                .registerService(AuthenticationDataPublisher.class.getName(), new DASSessionDataPublisherImpl(), null);
        bundleContext
                .registerService(AuthenticationDataPublisher.class.getName(), new AuthnDataPublisherProxy(), null);
    }

    protected void setEventStreamService(EventStreamService publisherService) {

        AuthenticationDataPublisherDataHolder.getInstance().setPublisherService(publisherService);
    }

    protected void unsetEventStreamService(EventStreamService publisherService) {

        AuthenticationDataPublisherDataHolder.getInstance().setPublisherService(null);
    }

    protected void setRealmService(RealmService realmService) {

        AuthenticationDataPublisherDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        AuthenticationDataPublisherDataHolder.getInstance().setRealmService(null);
    }

    protected void setRegistryService(RegistryService registryService) {

        AuthenticationDataPublisherDataHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {

        AuthenticationDataPublisherDataHolder.getInstance().setRegistryService(null);
    }

    protected void setAuthenticationDataPublisher(AuthenticationDataPublisher publisher) {
        if (!FrameworkConstants.AnalyticsAttributes.AUTHN_DATA_PUBLISHER_PROXY.equalsIgnoreCase(publisher.getName())) {
            AuthenticationDataPublisherDataHolder.getInstance().getDataPublishers().add(publisher);
        }
    }

    protected void unsetAuthenticationDataPublisher(AuthenticationDataPublisher publisher) {
        AuthenticationDataPublisherDataHolder.getInstance().getDataPublishers().remove(publisher);
    }

}
