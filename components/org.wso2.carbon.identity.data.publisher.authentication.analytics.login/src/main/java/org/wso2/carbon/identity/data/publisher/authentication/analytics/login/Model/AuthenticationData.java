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

package org.wso2.carbon.identity.data.publisher.application.authentication.model;

import org.wso2.carbon.identity.base.IdentityRuntimeException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class AuthenticationData<T1 extends Object, T2 extends Object> {

    private String eventId;
    private String contextId;
    private String eventType;
    private String identityProviderType;
    private boolean authnSuccess;
    private String username;
    private String localUsername;
    private String userStoreDomain;
    private String tenantDomain;
    private String remoteIp;
    private String serviceProvider;
    private String inboundProtocol;
    private boolean rememberMe;
    private boolean forcedAuthn;
    private boolean passive;
    private boolean initialLogin;
    private int stepNo;
    private String identityProvider;
    private String authenticator;
    private boolean success;
    protected Map<T1, T2> parameters = new HashMap<>();

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

    public String getLocalUsername() {
        return localUsername;
    }

    public void setLocalUsername(String localUsername) {
        this.localUsername = localUsername;
    }

    public String getIdentityProviderType() {

        return identityProviderType;
    }

    public void setIdentityProviderType(String identityProviderType) {

        this.identityProviderType = identityProviderType;
    }

    public boolean isAuthnSuccess() {

        return authnSuccess;
    }

    public void setAuthnSuccess(boolean authnSuccess) {

        this.authnSuccess = authnSuccess;
    }

    public String getUsername() {

        return username;
    }

    public void setUsername(String username) {

        this.username = username;
    }

    public String getUserStoreDomain() {

        return userStoreDomain;
    }

    public void setUserStoreDomain(String userStoreDomain) {

        this.userStoreDomain = userStoreDomain;
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

    public boolean isRememberMe() {

        return rememberMe;
    }

    public void setRememberMe(boolean rememberMe) {

        this.rememberMe = rememberMe;
    }

    public boolean isForcedAuthn() {

        return forcedAuthn;
    }

    public void setForcedAuthn(boolean forcedAuthn) {

        this.forcedAuthn = forcedAuthn;
    }

    public boolean isPassive() {

        return passive;
    }

    public void setPassive(boolean passive) {

        this.passive = passive;
    }

    public boolean isInitialLogin() {

        return initialLogin;
    }

    public void setInitialLogin(boolean initialLogin) {

        this.initialLogin = initialLogin;
    }

    public int getStepNo() {

        return stepNo;
    }

    public void setStepNo(int stepNo) {

        this.stepNo = stepNo;
    }

    public String getIdentityProvider() {

        return identityProvider;
    }

    public void setIdentityProvider(String identityProvider) {

        this.identityProvider = identityProvider;
    }

    public boolean isSuccess() {

        return success;
    }

    public void setSuccess(boolean success) {

        this.success = success;
    }

    public String getAuthenticator() {

        return authenticator;
    }

    public void setAuthenticator(String authenticator) {

        this.authenticator = authenticator;
    }

    public void addParameter(T1 key, T2 value) {
        if (this.parameters.containsKey(key)) {
            throw IdentityRuntimeException.error("Parameters map trying to override existing key " +
                    key);
        }
        parameters.put(key, value);
    }

    public void addParameters(Map<T1, T2> parameters) {
        for (Map.Entry<T1, T2> parameter : parameters.entrySet()) {
            if (this.parameters.containsKey(parameter.getKey())) {
                throw IdentityRuntimeException.error("Parameters map trying to override existing key " + parameter.getKey());
            }
            parameters.put(parameter.getKey(), parameter.getValue());
        }
    }

    public Map<T1, T2> getParameters() {
        return Collections.unmodifiableMap(parameters);
    }

    public T2 getParameter(T1 key) {
        return parameters.get(key);
    }

}
