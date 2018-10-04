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

package org.wso2.carbon.identity.data.publisher.authentication.analytics.session;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.event.stream.core.internal.CarbonEventStreamService;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;
import static org.mockito.Mockito.mock;

import java.util.HashMap;
import java.util.Map;

/**
 * Unit tests related to AnalyticsSessionDataPublishHandler class.
 */
public class AnalyticsSessionDataPublishHandlerTest extends IdentityBaseTest {

    AnalyticsSessionDataPublishHandler analyticsSessionDataPublishHandler = new AnalyticsSessionDataPublishHandler();
    org.wso2.carbon.databridge.commons.Event event = mock(org.wso2.carbon.databridge.commons.Event.class);

    @Test
    public void testGetName() {
        Assert.assertEquals(analyticsSessionDataPublishHandler.getName(), "analyticsSessionDataPublisher");
    }

    @Test
    public void testHandleEvent() {
        MockEventService mockEventService = new MockEventService();
        mockEventService.publish(event);
        Assert.assertEquals(mockEventService.getEvents().size(), 1);
    }

    private static class MockEventService extends CarbonEventStreamService {

        private Map<String, org.wso2.carbon.databridge.commons.Event> events = new HashMap<>();

        public void publish(org.wso2.carbon.databridge.commons.Event event) {
            events.put("some event", event);
        }

        public Map<String, org.wso2.carbon.databridge.commons.Event> getEvents() {
            return this.events;
        }
    }

}
