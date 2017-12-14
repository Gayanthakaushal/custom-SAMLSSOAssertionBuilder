package com.org.lk;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnStatement;
import org.wso2.carbon.identity.sso.saml.builders.assertion.DefaultSAMLAssertionBuilder;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.idp.mgt.util.IdPManagementUtil;

import java.util.concurrent.TimeUnit;

public class App extends DefaultSAMLAssertionBuilder
{
    protected void addAuthStatement(SAMLSSOAuthnReqDTO authReqDTO, String sessionId, Assertion samlAssertion) {
        super.addAuthStatement(authReqDTO, sessionId, samlAssertion);

        AuthnStatement authnStatement = samlAssertion.getAuthnStatements().get(0);

        DateTime sessionNotOnOrAfter = new DateTime(authnStatement.getAuthnInstant().getMillis() + TimeUnit.SECONDS.toMillis((long) IdPManagementUtil.getIdleSessionTimeOut(authReqDTO.getTenantDomain())));
        authnStatement.setSessionNotOnOrAfter(sessionNotOnOrAfter);

        samlAssertion.getAuthnStatements().add(authnStatement);


    }

}
