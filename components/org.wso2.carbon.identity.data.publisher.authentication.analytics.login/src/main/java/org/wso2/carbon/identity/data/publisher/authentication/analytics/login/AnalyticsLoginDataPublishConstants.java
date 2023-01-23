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

/**
 * Contains constants for analytics login data publisher.
 */
public class AnalyticsLoginDataPublishConstants {

    public static final String ANALYTICS_LOGIN_PUBLISHER_NAME = "analyticsLoginDataPublisher";
    public static final String AUTHN_DATA_STREAM_NAME = "org.wso2.is.analytics.stream.OverallAuthentication:1.0.0";
    public static final String AUTHN_DATA_STREAM_1_1_0_NAME =
            "org.wso2.is.analytics.stream.OverallAuthentication:1.1.0";
    public static final String TENANT_DOMAIN_NAMES = "tenantDomainNames";

    // Event types
    public static final String STEP_EVENT = "step";
    public static final String OVERALL_EVENT = "overall";

    public static final String ANALYTICS_LOGIN_DATA_PUBLISHER_ENABLED = "analyticsLoginDataPublisher.enable";
    public static final String ANALYTICS_LOGIN_DATA_PUBLISHER_ENABLE_MULTIPLE_EVENT_PUBLISHING_FOR_SAAS_APPS =
            "analyticsLoginDataPublisher.enableMultipleEventPublishingForSaasApps";
    public static final String ANALYTICS_LOGIN_DATA_PUBLISHER_V110_ENABLED = "analyticsLoginDataPublisherV110.enable";
    public static final long LONG_NOT_AVAILABLE = 0;
    public static final String ANALYTICS_LOGIN_PUBLISHER_V110_NAME = "analyticsLoginDataPublisherV110";
    public static final String IS_INVALID_USERNAME = "isInvalidUsername";

    public static final String USERNAME_USER_INPUT = "usernameUserInput";

    private AnalyticsLoginDataPublishConstants() {

    }
}
