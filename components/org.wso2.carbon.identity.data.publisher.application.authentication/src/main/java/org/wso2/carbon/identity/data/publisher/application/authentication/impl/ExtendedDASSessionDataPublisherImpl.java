package org.wso2.carbon.identity.data.publisher.application.authentication.impl;

import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

public class ExtendedDASSessionDataPublisherImpl extends DASLoginDataPublisherImpl {

    private boolean doPublishStepAuthenticationData = false;

    @Override
    public void publishAuthenticationStepSuccess(HttpServletRequest request,
                                                 AuthenticationContext context,
                                                 Map<String, Object> params) {

        if (doPublishStepAuthenticationData) {
            super.publishAuthenticationStepSuccess(request, context, params);
        }
    }


    @Override
    public void publishAuthenticationStepFailure(HttpServletRequest request,
                                                 AuthenticationContext context,
                                                 Map<String, Object> params) {

        if (doPublishStepAuthenticationData) {
            super.publishAuthenticationStepFailure(request, context, params);
        }
    }
}
