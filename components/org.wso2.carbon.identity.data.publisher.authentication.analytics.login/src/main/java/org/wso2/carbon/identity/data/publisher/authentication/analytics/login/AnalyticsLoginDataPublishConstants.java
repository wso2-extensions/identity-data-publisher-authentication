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

/*
 * Contains constants for analytics login data publisher
 */
public class AnalyticsLoginDataPublishConstants {

    public static final String ANALYTICS_LOGIN_PUBLISHER_NAME = "DASLoginDataPublisher";
    public static final String AUTHN_DATA_STREAM_NAME = "org.wso2.is.analytics.stream.OverallAuthentication:1.0.0";

    public static final String NOT_AVAILABLE = "NOT_AVAILABLE";
    public static final String CONFIG_PREFIX = "ISAnalytics.DefaultValues.";
    public static final String USERNAME = "userName";
    public static final String ROLES = "rolesCommaSeperated";
    public static final String SERVICE_PROVIDER = "serviceprovider";
    public static final String IDENTITY_PROVIDER = "identityProvider";
    public static final String USER_STORE_DOMAIN = "userStoreDomain";
    public static final String TENANT_ID = "tenantId";
    public static final String RELYING_PARTY = "relyingParty";
    public static final String SUBJECT_IDENTIFIER = "subjectIdentifier";
    public static final String AUTHENTICATED_IDPS = "authenticatedIDPs";

    // Event types
    public static final String STEP_EVENT = "step";
    public static final String OVERALL_EVENT = "overall";
}