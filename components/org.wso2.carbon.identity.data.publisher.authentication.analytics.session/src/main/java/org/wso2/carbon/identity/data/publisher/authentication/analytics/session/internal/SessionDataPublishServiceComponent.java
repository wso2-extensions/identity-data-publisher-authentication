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

package org.wso2.carbon.identity.data.publisher.authentication.analytics.session.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.session.AnalyticsSessionDataPublishHandler;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;

/*
 * Service registering class for session data publish of analytics
 */

/**
 * @scr.component name="identity.data.publisher.authentication.analytics.session" immediate="true"
 * @scr.reference name="eventStreamManager.service"
 * interface="org.wso2.carbon.event.stream.core.EventStreamService" cardinality="1..1"
 * policy="dynamic" bind="setEventStreamService" unbind="unsetEventStreamService"
 */

public class SessionDataPublishServiceComponent {

    private static Log log = LogFactory.getLog(SessionDataPublishServiceComponent.class);

    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleContext = context.getBundleContext();
            bundleContext.registerService(AbstractEventHandler.class,
                    new AnalyticsSessionDataPublishHandler(), null);

            if (log.isDebugEnabled()) {
                log.debug("org.wso2.carbon.identity.data.publisher.authentication.analytics.session" +
                        " bundle is activated");
            }
        } catch (Exception e) {
            log.error("Error while activating org.wso2.carbon.identity.data.publisher.authentication" +
                    ".analytics.session", e);
        }
    }

    protected void setEventStreamService(EventStreamService eventStreamService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Event Stream Service");
        }
        SessionDataPublishServiceHolder.getInstance().setPublisherService(eventStreamService);
    }

    protected void unsetEventStreamService(EventStreamService eventStreamService) {

        if (log.isDebugEnabled()) {
            log.debug("Un-setting the Event Stream Service");
        }
        SessionDataPublishServiceHolder.getInstance().setPublisherService(null);
    }

}
