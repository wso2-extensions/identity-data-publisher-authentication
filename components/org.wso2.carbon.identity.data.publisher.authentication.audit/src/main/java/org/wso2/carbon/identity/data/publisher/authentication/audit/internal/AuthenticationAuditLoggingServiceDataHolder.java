package org.wso2.carbon.identity.data.publisher.authentication.audit.internal;

import org.wso2.carbon.identity.organization.management.service.OrganizationManager;

/**
 * Data holder for authentication audit logging service.
 */
public class AuthenticationAuditLoggingServiceDataHolder {

    private static final AuthenticationAuditLoggingServiceDataHolder instance =
            new AuthenticationAuditLoggingServiceDataHolder();

    private OrganizationManager organizationManager;

    public static AuthenticationAuditLoggingServiceDataHolder getInstance() {

        return instance;
    }

    public OrganizationManager getOrganizationManager() {

        return organizationManager;
    }

    public void setOrganizationManager(
            OrganizationManager organizationManager) {

        this.organizationManager = organizationManager;
    }
}
