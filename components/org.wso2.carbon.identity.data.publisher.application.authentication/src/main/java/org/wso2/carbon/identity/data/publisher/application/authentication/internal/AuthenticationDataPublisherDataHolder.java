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

import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationDataPublisher;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.List;

public class AuthenticationDataPublisherDataHolder {

    private static AuthenticationDataPublisherDataHolder
            serviceHolder = new AuthenticationDataPublisherDataHolder();
    private List<AuthenticationDataPublisher> dataPublishers = new ArrayList<>();
    private IdentityEventService identityEventService;
    private EventStreamService eventStreamService;
    private RealmService realmService;

    private AuthenticationDataPublisherDataHolder() {

    }

    public static AuthenticationDataPublisherDataHolder getInstance() {

        return serviceHolder;
    }

    public List<AuthenticationDataPublisher> getDataPublishers() {

        return dataPublishers;
    }

    public IdentityEventService getIdentityEventService() {

        return identityEventService;
    }

    public void setIdentityEventService(IdentityEventService identityEventService) {

        this.identityEventService = identityEventService;
    }

    public EventStreamService getPublisherService() {

        return eventStreamService;
    }

    public void setPublisherService(EventStreamService eventStreamService) {

        this.eventStreamService = eventStreamService;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }
}
