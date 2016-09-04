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

import org.wso2.carbon.identity.application.authentication.framework.AuthenticationDataPublisher;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;
import org.wso2.carbon.identity.core.handler.MessageHandlerComparator;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.data.publisher.application.authentication.internal.AuthenticationDataPublisherDataHolder;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class AuthnDataPublisherProxy extends AbstractIdentityMessageHandler implements
        AuthenticationDataPublisher {

    private List<AuthenticationDataPublisher> dataPublishers = AuthenticationDataPublisherDataHolder.getInstance()
            .getDataPublishers();

    /**
     * Publish authentication success after managing handler operations
     *
     * @param request Request which comes to the framework for authentication
     * @param context Authentication context
     * @param params  Other parameters which are need to be passed
     */
    public void publishAuthenticationStepSuccess(HttpServletRequest request, AuthenticationContext context,
                                                 Map<String, Object> params) {
        for (AuthenticationDataPublisher publisher : dataPublishers) {
            if (publisher.isEnabled(context) && publisher.canHandle(context)) {
                publisher.publishAuthenticationStepSuccess(request, context, params);
            }
        }
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
        for (AuthenticationDataPublisher publisher : dataPublishers) {
            if (publisher.isEnabled(context) && publisher.canHandle(context)) {
                publisher.publishAuthenticationStepFailure(request, context, unmodifiableMap);
            }
        }

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
        for (AuthenticationDataPublisher publisher : dataPublishers) {
            if (publisher != null && publisher.isEnabled(context) && publisher.canHandle(context)) {
                publisher.publishAuthenticationSuccess(request, context, unmodifiableMap);
            }
        }

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
        for (AuthenticationDataPublisher publisher : dataPublishers) {
            if (publisher != null && publisher.isEnabled(context) && publisher.canHandle(context)) {
                publisher.publishAuthenticationFailure(request, context, unmodifiableMap);
            }
        }
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
        for (AuthenticationDataPublisher publisher : dataPublishers) {
            if (publisher != null && publisher.isEnabled(context) && publisher.canHandle(context)) {
                publisher.publishSessionCreation(request, context, sessionContext, unmodifiableMap);
            }
        }
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
        for (AuthenticationDataPublisher publisher : dataPublishers) {
            if (publisher != null && publisher.isEnabled(context) && publisher.canHandle(context)) {
                publisher.publishSessionUpdate(request, context, sessionContext, unmodifiableMap);
            }
        }

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
        for (AuthenticationDataPublisher publisher : dataPublishers) {
            if (publisher != null && publisher.isEnabled(context) && publisher.canHandle(context)) {
                publisher.publishSessionTermination(request, context, sessionContext, unmodifiableMap);
            }
        }
    }

    @Override
    public String getName() {
        return FrameworkConstants.AnalyticsAttributes.AUTHN_DATA_PUBLISHER_PROXY;
    }
}
