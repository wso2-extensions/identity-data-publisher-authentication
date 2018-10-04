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

import static org.mockito.Mockito.*;
import static org.testng.Assert.*;
import org.testng.annotations.Test;
import org.wso2.carbon.databridge.commons.Event;
import org.wso2.carbon.event.stream.core.internal.CarbonEventStreamService;

import java.util.HashMap;
import java.util.Map;

/**
 * Unit tests related to AnalyticsLoginDataPublishHandler class.
 */
public class AnalyticsLoginDataPublishHandlerTest {

    AnalyticsLoginDataPublishHandler analyticsLoginDataPublishHandler = new AnalyticsLoginDataPublishHandler();
    org.wso2.carbon.databridge.commons.Event event = mock(org.wso2.carbon.databridge.commons.Event.class);

    @Test
    public void testGetName() { assertEquals(analyticsLoginDataPublishHandler.getName(), "analyticsLoginDataPublisher"); }

    @Test
    public void testPublishAuthenticationData() {
        MockEventService mockEventService = new MockEventService();
        mockEventService.publish(event);
        assertEquals(mockEventService.getEvents().size(), 1);
    }

    private static class MockEventService extends CarbonEventStreamService {

        private Map<String, Event> events = new HashMap<>();

        public void publish(Event event) {
            events.put("some event", event);
        }

        public Map<String, Event> getEvents() {
            return this.events;
        }
    }

}
