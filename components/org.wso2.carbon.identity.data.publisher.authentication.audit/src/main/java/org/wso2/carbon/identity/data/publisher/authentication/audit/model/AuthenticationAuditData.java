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

package org.wso2.carbon.identity.data.publisher.authentication.audit.model;

/**
 * Data object class for authentication audit logger.
 */
public class AuthenticationAuditData {

    private String contextIdentifier;
    private String authenticatedUser;
    private String tenantDomain;
    private String serviceProvider;
    private String inboundProtocol;
    private String relyingParty;
    private String authenticatedIdps;
    private String userStoreDomain;
    private int stepNo;

    public String getContextIdentifier() {

        return contextIdentifier;
    }

    public void setContextIdentifier(String contextIdentifier) {

        this.contextIdentifier = contextIdentifier;
    }

    public String getAuthenticatedUser() {

        return authenticatedUser;
    }

    public void setAuthenticatedUser(String authenticatedUser) {

        this.authenticatedUser = authenticatedUser;
    }

    public String getTenantDomain() {

        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {

        this.tenantDomain = tenantDomain;
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

    public String getRelyingParty() {

        return relyingParty;
    }

    public void setRelyingParty(String relyingParty) {

        this.relyingParty = relyingParty;
    }

    public String getAuthenticatedIdps() {

        return authenticatedIdps;
    }

    public void setAuthenticatedIdps(String authenticatedIdps) {

        this.authenticatedIdps = authenticatedIdps;
    }

    public int getStepNo() {

        return stepNo;
    }

    public void setStepNo(int stepNo) {

        this.stepNo = stepNo;
    }

    public String getUserStoreDomain() {

        return userStoreDomain;
    }

    public void setUserStoreDomain(String userStoreDomain) {

        this.userStoreDomain = userStoreDomain;
    }
}
