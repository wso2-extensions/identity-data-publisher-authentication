/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.data.publisher.application.authentication;

import java.net.URL;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.idp.mgt.util.IdPManagementUtil;

import java.io.File;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.testng.Assert.assertEquals;

/**
 * Unit tests for AuthnDataPublisherUtils.
 */
public class AuthnDataPublisherUtilsTest {

    private MockedStatic<IdPManagementUtil> idPManagementUtilMock;
    
    private static final String TEST_TENANT = "test.tenant.com";
    private static final int REMEMBER_ME_TIMEOUT = 1209600; // 14 days in seconds.
    private static final int IDLE_SESSION_TIMEOUT = 900; // 15 minutes in seconds.
    private static final int MAX_SESSION_TIMEOUT = 3600; // 1 hour in seconds.

    @BeforeSuite
    public void setUpSuite() {

        URL root = this.getClass().getClassLoader().getResource(".");
        File file = new File(root.getPath());
        System.setProperty("carbon.home", file.getAbsolutePath());
    }

    @BeforeMethod
    public void setUp() {

        idPManagementUtilMock = Mockito.mockStatic(IdPManagementUtil.class);
    }

    @AfterMethod
    public void tearDown() {

        if (idPManagementUtilMock != null) {
            idPManagementUtilMock.close();
        }
    }

    @Test
    public void testGetSessionExpirationTimeWithRememberMe() {

        long createdTime = System.currentTimeMillis();
        long updatedTime = createdTime + TimeUnit.MINUTES.toMillis(10);
        
        idPManagementUtilMock.when(() -> IdPManagementUtil.getRememberMeTimeout(TEST_TENANT))
                .thenReturn(REMEMBER_ME_TIMEOUT);
        idPManagementUtilMock.when(() -> IdPManagementUtil.getMaximumSessionTimeout(TEST_TENANT))
                .thenReturn(Optional.empty());

        long expirationTime = AuthnDataPublisherUtils.getSessionExpirationTime(
                createdTime, updatedTime, TEST_TENANT, true);

        long expectedExpiration = createdTime + TimeUnit.SECONDS.toMillis(REMEMBER_ME_TIMEOUT);
        assertEquals(expirationTime, expectedExpiration, 
                "Expiration time should be createdTime + rememberMeTimeout when remember me is enabled");
    }

    @Test
    public void testGetSessionExpirationTimeWithIdleTimeout() {

        long createdTime = System.currentTimeMillis();
        long updatedTime = createdTime + TimeUnit.MINUTES.toMillis(10);
        
        idPManagementUtilMock.when(() -> IdPManagementUtil.getIdleSessionTimeOut(TEST_TENANT))
                .thenReturn(IDLE_SESSION_TIMEOUT);
        idPManagementUtilMock.when(() -> IdPManagementUtil.getMaximumSessionTimeout(TEST_TENANT))
                .thenReturn(Optional.empty());

        long expirationTime = AuthnDataPublisherUtils.getSessionExpirationTime(
                createdTime, updatedTime, TEST_TENANT, false);

        long expectedExpiration = updatedTime + TimeUnit.SECONDS.toMillis(IDLE_SESSION_TIMEOUT);
        assertEquals(expirationTime, expectedExpiration, 
                "Expiration time should be updatedTime + idleSessionTimeout when remember me is disabled");
    }

    @Test
    public void testGetSessionExpirationTimeWithMaxSessionTimeoutExceeded() {

        long createdTime = System.currentTimeMillis();
        long updatedTime = createdTime + TimeUnit.MINUTES.toMillis(10);

        idPManagementUtilMock.when(() -> IdPManagementUtil.getRememberMeTimeout(TEST_TENANT))
                .thenReturn(REMEMBER_ME_TIMEOUT);
        idPManagementUtilMock.when(() -> IdPManagementUtil.getMaximumSessionTimeout(TEST_TENANT))
                .thenReturn(Optional.of(MAX_SESSION_TIMEOUT));

        long expirationTime = AuthnDataPublisherUtils.getSessionExpirationTime(
                createdTime, updatedTime, TEST_TENANT, true);

        long expectedExpiration = createdTime + TimeUnit.SECONDS.toMillis(MAX_SESSION_TIMEOUT);
        assertEquals(expirationTime, expectedExpiration, 
                "Expiration time should be capped at maxSessionTimeout when calculated expiration exceeds it");
    }

    @Test
    public void testGetSessionExpirationTimeWithMaxSessionTimeoutNotExceeded() {

        long createdTime = System.currentTimeMillis();
        long updatedTime = createdTime + TimeUnit.MINUTES.toMillis(10);

        idPManagementUtilMock.when(() -> IdPManagementUtil.getIdleSessionTimeOut(TEST_TENANT))
                .thenReturn(IDLE_SESSION_TIMEOUT);
        idPManagementUtilMock.when(() -> IdPManagementUtil.getMaximumSessionTimeout(TEST_TENANT))
                .thenReturn(Optional.of(MAX_SESSION_TIMEOUT));

        long expirationTime = AuthnDataPublisherUtils.getSessionExpirationTime(
                createdTime, updatedTime, TEST_TENANT, false);

        long expectedExpiration = updatedTime + TimeUnit.SECONDS.toMillis(IDLE_SESSION_TIMEOUT);
        assertEquals(expirationTime, expectedExpiration, 
                "Expiration time should be calculated normally when it doesn't exceed maxSessionTimeout");
    }

    @Test
    public void testGetSessionExpirationTimeWithRememberMeAndMaxTimeout() {

        long createdTime = System.currentTimeMillis();
        long updatedTime = createdTime + TimeUnit.HOURS.toMillis(2);

        int rememberMeTimeout = 36000; // 10 hours in seconds.
        int maxTimeout = 18000; // 5 hours in seconds.
        
        idPManagementUtilMock.when(() -> IdPManagementUtil.getRememberMeTimeout(TEST_TENANT))
                .thenReturn(rememberMeTimeout);
        idPManagementUtilMock.when(() -> IdPManagementUtil.getMaximumSessionTimeout(TEST_TENANT))
                .thenReturn(Optional.of(maxTimeout));

        long expirationTime = AuthnDataPublisherUtils.getSessionExpirationTime(
                createdTime, updatedTime, TEST_TENANT, true);

        long expectedExpiration = createdTime + TimeUnit.SECONDS.toMillis(maxTimeout);
        assertEquals(expirationTime, expectedExpiration, 
                "Expiration time should be capped at maxSessionTimeout even with remember me enabled");
    }
}
