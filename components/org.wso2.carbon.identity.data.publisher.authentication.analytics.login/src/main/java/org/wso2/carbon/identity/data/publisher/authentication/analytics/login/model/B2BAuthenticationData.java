/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.data.publisher.authentication.analytics.login.model;

/**
 * Data object class for B2B authentication data.
 */
public class B2BAuthenticationData {

    private String eventId;
    private String contextId;
    private String eventType;
    private String username;
    private String userId;
    private String tenantDomain;
    private String remoteIp;
    private String serviceProvider;
    private String inboundProtocol;
    private boolean isOrganizationLogin;
    private String organizationName;

    public String getEventId() {

        return eventId;
    }

    public void setEventId(String eventId) {

        this.eventId = eventId;
    }

    public String getContextId() {

        return contextId;
    }

    public void setContextId(String contextId) {

        this.contextId = contextId;
    }

    public String getEventType() {

        return eventType;
    }

    public void setEventType(String eventType) {

        this.eventType = eventType;
    }

    public String getUsername() {

        return username;
    }

    public void setUsername(String username) {

        this.username = username;
    }

    public String getUserId() {

        return userId;
    }

    public void setUserId(String userId) {

        this.userId = userId;
    }

    public String getTenantDomain() {

        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {

        this.tenantDomain = tenantDomain;
    }

    public String getRemoteIp() {

        return remoteIp;
    }

    public void setRemoteIp(String remoteIp) {

        this.remoteIp = remoteIp;
    }

    public String getServiceProvider() {

        return serviceProvider;
    }

    public void setServiceProvider(String serviceProvider) {

        this.serviceProvider = serviceProvider;
    }

    public String getInboundProtocol() {

        return inboundProtocol;
    }

    public void setInboundProtocol(String inboundProtocol) {

        this.inboundProtocol = inboundProtocol;
    }

    public boolean isOrganizationLogin() {

        return isOrganizationLogin;
    }

    public void setOrganizationLogin(boolean organizationLogin) {

        isOrganizationLogin = organizationLogin;
    }

    public String getOrganizationName() {

        return organizationName;
    }

    public void setOrganizationName(String organizationName) {

        this.organizationName = organizationName;
    }
}
