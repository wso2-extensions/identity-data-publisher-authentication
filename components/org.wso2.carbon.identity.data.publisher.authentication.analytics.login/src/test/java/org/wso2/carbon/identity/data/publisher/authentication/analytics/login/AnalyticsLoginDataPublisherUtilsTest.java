/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.when;

import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.login.model.AuthenticationData;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

@PrepareForTest({ AuthenticationContext.class })
public class AnalyticsLoginDataPublisherUtilsTest {

    private static final String TENANT_DOMAIN = "abc.com";
    private static final String USER_ID = "940ef81d-ea35-483e-aa5d-7e55c269e8cc";

    @Mock
    HttpServletRequest mockHttpServletRequest;
    @Mock
    AuthenticationContext mockAuthenticationContext;
    @Mock
    SessionContext mockSessionContext;

    @BeforeTest
    public void setUp() {
        initMocks(this);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(null);
    }

    @DataProvider(name = "getEvent")
    public Object[][] getEvent() {
        Map<String, Object> param = new HashMap<>();
        Object userObj = new AuthenticatedUser();
        ((AuthenticatedUser) userObj).setTenantDomain(TENANT_DOMAIN);
        ((AuthenticatedUser) userObj).setUserId(USER_ID);
        param.put(FrameworkConstants.AnalyticsAttributes.USER, userObj);
        Event event = createEvent(mockHttpServletRequest, mockAuthenticationContext, mockSessionContext, param,
                IdentityEventConstants.EventName.AUTHENTICATION_STEP_SUCCESS);

        return new Object[][] {
                { event, TENANT_DOMAIN},
                };
    }

    @Test(dataProvider = "getEvent")
    public void testBuildAuthnDataForAuthnStep(Event event, String expectedTenantDomain) {

        AuthenticationData authenticationData = AnalyticsLoginDataPublisherUtils.buildAuthnDataForAuthnStep(event);
        Assert.assertEquals(authenticationData.getTenantDomain(), expectedTenantDomain);
    }

    @Test(dataProvider = "getEvent")
    public void testBuildAuthnDataForAuthentication(Event event, String expectedTenantDomain) {

        AuthenticationData authenticationData = AnalyticsLoginDataPublisherUtils.buildAuthnDataForAuthentication(event);
        Assert.assertEquals(authenticationData.getTenantDomain(), expectedTenantDomain);
    }

    private Event createEvent(HttpServletRequest request, AuthenticationContext context, SessionContext sessionContext,
            Map<String, Object> params, IdentityEventConstants.EventName eventName) {

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.REQUEST, request);
        eventProperties.put(IdentityEventConstants.EventProperty.CONTEXT, context);
        if (sessionContext != null) {
            eventProperties.put(IdentityEventConstants.EventProperty.SESSION_CONTEXT, sessionContext);
        }
        eventProperties.put(IdentityEventConstants.EventProperty.PARAMS, params);
        return new Event(eventName.name(), eventProperties);
    }
}
