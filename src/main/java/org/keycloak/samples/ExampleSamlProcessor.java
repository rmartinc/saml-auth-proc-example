/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.samples;

import java.net.URI;
import java.net.URISyntaxException;
import org.keycloak.Config;
import org.keycloak.dom.saml.v2.protocol.AuthnContextComparisonType;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.RequestedAuthnContextType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.saml.preprocessor.SamlAuthenticationPreprocessor;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * <p>Sample class that implements SamlAuthenticationPreprocessor and implements
 * beforeSendingLoginRequest to add an example RequestedAuthnContext. The idea
 * is this is executed in every broker request and the RequestedAuthnContext is
 * added if it's end to a specific URL/SAML endpoint.</p>
 *
 * <p>It's just a direct example, adapt it to your needs.</p>
 *
 * @author rmartinc
 */
public class ExampleSamlProcessor implements SamlAuthenticationPreprocessor {

    @Override
    public AuthnRequestType beforeSendingLoginRequest(AuthnRequestType authnRequest,
            AuthenticationSessionModel clientSession) {
        // only add the auth context if it's to our SAML broker endpoint
        // change this to your needs
        try {
            if (new URI("http://localhost:8080/auth/realms/master/broker/broker-saml-realm/endpoint").equals(authnRequest.getAssertionConsumerServiceURL())) {
                System.err.println("Adding the RequestedAuthnContext...");
                RequestedAuthnContextType authCtx = authnRequest.getRequestedAuthnContext();
                if (authCtx == null) {
                    authCtx = new RequestedAuthnContextType();
                    authnRequest.setRequestedAuthnContext(authCtx);
                }
                authCtx.setComparison(AuthnContextComparisonType.EXACT);
                authCtx.addAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes");
            }
        } catch (URISyntaxException e) {

        }
        return authnRequest;
    }

    // Provider and ProviderFactory

    @Override
    public void close() {
    }

    @Override
    public SamlAuthenticationPreprocessor create(KeycloakSession ks) {
        return new ExampleSamlProcessor();
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory ksf) {
    }

    @Override
    public String getId() {
        return "ExampleSamlProcessor";
    }
}
