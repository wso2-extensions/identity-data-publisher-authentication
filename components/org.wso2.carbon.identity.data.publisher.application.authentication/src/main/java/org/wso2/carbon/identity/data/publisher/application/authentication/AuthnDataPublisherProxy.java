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

package org.wso2.carbon.identity.data.publisher.application.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationDataPublisher;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;
import org.wso2.carbon.identity.data.publisher.application.authentication.internal.AuthenticationDataPublisherDataHolder;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

public class AuthnDataPublisherProxy extends AbstractIdentityMessageHandler implements
        AuthenticationDataPublisher {
    private static final Log log = LogFactory.getLog(AuthnDataPublisherProxy.class);

    /**
     * Publish authentication success after managing handler operations
     *
     * @param request Request which comes to the framework for authentication
     * @param context Authentication context
     * @param params  Other parameters which are need to be passed
     */
    public void publishAuthenticationStepSuccess(HttpServletRequest request, AuthenticationContext context,
                                                 Map<String, Object> params) {
        Event event = initiateEvent(request, context, null, params, IdentityEventConstants.EventName
                .AUTHENTICATION_STEP_SUCCESS.toString());
        doPublishEvent(event);
    }

    /**
     * Published authentication step failure after managing handler operations
     *
     * @param request         Incoming Http request to framework for authentication
     * @param context         Authentication Context
     * @param unmodifiableMap Other relevant parameters which needs to be published
     */
    public void publishAuthenticationStepFailure(HttpServletRequest request, AuthenticationContext context,
                                                 Map<String, Object> unmodifiableMap) {
        Event event = initiateEvent(request, context, null, unmodifiableMap, IdentityEventConstants.EventName
                .AUTHENTICATION_STEP_FAILURE.toString());
        doPublishEvent(event);
    }

    /**
     * Publishes authentication success after managing handler operations
     *
     * @param request         Incoming request for authentication
     * @param context         Authentication context
     * @param unmodifiableMap Other relevant parameters which needs to be published
     */
    public void publishAuthenticationSuccess(HttpServletRequest request, AuthenticationContext context,
                                             Map<String, Object> unmodifiableMap) {
        Event event = initiateEvent(request, context, null, unmodifiableMap, IdentityEventConstants.EventName
                .AUTHENTICATION_SUCCESS.toString());
        doPublishEvent(event);
    }

    /**
     * Publishes authentication failure after managing handler operations
     *
     * @param request         Incoming authentication request
     * @param context         Authentication context
     * @param unmodifiableMap Other relevant parameters which needs to be published
     */
    public void publishAuthenticationFailure(HttpServletRequest request, AuthenticationContext context,
                                             Map<String, Object> unmodifiableMap) {
        Event event = initiateEvent(request, context, null, unmodifiableMap, IdentityEventConstants.EventName
                .AUTHENTICATION_FAILURE.toString());
        doPublishEvent(event);
    }

    /**
     * Publishes session creation information after managing handler operations
     *
     * @param request         Incoming request for authentication
     * @param context         Authentication Context
     * @param sessionContext  Session context
     * @param unmodifiableMap Other relevant parameters which needs to be published
     */
    public void publishSessionCreation(HttpServletRequest request, AuthenticationContext context, SessionContext
            sessionContext, Map<String, Object> unmodifiableMap) {
        Event event = initiateEvent(request, context, sessionContext, unmodifiableMap, IdentityEventConstants.EventName
                .SESSION_CREATE.toString());
        doPublishEvent(event);
    }

    /**
     * Publishes session update after managing handler operations
     *
     * @param request         Incoming request for authentication
     * @param context         Authentication context
     * @param sessionContext  Session context
     * @param unmodifiableMap Other relevant parameters which needs to be published
     */

    public void publishSessionUpdate(HttpServletRequest request, AuthenticationContext context, SessionContext
            sessionContext, Map<String, Object> unmodifiableMap) {
        Event event = initiateEvent(request, context, sessionContext, unmodifiableMap, IdentityEventConstants.EventName
                .SESSION_UPDATE.toString());
        doPublishEvent(event);
    }

    /**
     * Publishes session termination
     *
     * @param request         Incoming request for authentication
     * @param context         Authentication context
     * @param sessionContext  Session context
     * @param unmodifiableMap Other relevant parameters which needs to be published
     */

    public void publishSessionTermination(HttpServletRequest request, AuthenticationContext context,
                                          SessionContext sessionContext, Map<String, Object> unmodifiableMap) {
        Event event = initiateEvent(request, context, sessionContext, unmodifiableMap, IdentityEventConstants.EventName
                .SESSION_TERMINATE.toString());
        doPublishEvent(event);
    }

    @Override
    public String getName() {
        return FrameworkConstants.AnalyticsAttributes.AUTHN_DATA_PUBLISHER_PROXY;
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {
        return true;
    }

    /**
     * initiate an event with following attributes as event properties and it will be sent to IdentityEventService for handling
     *
     * @param request
     * @param context
     * @param sessionContext
     * @param params
     * @param eventName
     * @return
     */
    private Event initiateEvent(HttpServletRequest request, AuthenticationContext context, SessionContext sessionContext,
                                Map<String, Object> params, String eventName) {
        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.REQUEST, request);
        eventProperties.put(IdentityEventConstants.EventProperty.CONTEXT, context);
        if (sessionContext != null) {
            eventProperties.put(IdentityEventConstants.EventProperty.SESSION_CONTEXT, sessionContext);
        }
        eventProperties.put(IdentityEventConstants.EventProperty.PARAMS, params);
        Event event = new Event(eventName, eventProperties);
        return event;
    }

    private void doPublishEvent(Event event) {
        try {
            AuthenticationDataPublisherDataHolder.getInstance().getIdentityEventService().handleEvent(event);
        } catch (IdentityEventException e) {
            log.error("Error is caught while handling the event: " + event.getEventName() + ".", e);
        }
    }
}
