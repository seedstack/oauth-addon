/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
/*
 * Creation : 20 Nov 2017
 */
package org.seedstack.oauth;

import java.net.URI;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformationResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;

public class OpenIdConnectClientRegistration {

    private final String registrationEndPoint = "http://127.0.0.1:8080/c2id/clients";
    // private final String callbackURL = "https://127.0.0.1:8080/oidc-client/cb";
    private final String callbackURL = "https://127.0.0.1:8081/callback";
    private final String bearerAccessTkn = "ztucZS1ZyFKgh0tUEruUtiSTXhnexmd6";

    public static void main(String[] args) {
        OpenIdConnectClientRegistration obj = new OpenIdConnectClientRegistration();
        obj.registerClient();
    }

    public void registerClient() {

        try {

            URI regEndpoint = new URI(registrationEndPoint);

            OIDCClientMetadata metadata = new OIDCClientMetadata();
            metadata.setRedirectionURI(new URI(callbackURL));
            metadata.setName("Client Registration App");

            BearerAccessToken accessToken = new BearerAccessToken(bearerAccessTkn);

            OIDCClientRegistrationRequest request = new OIDCClientRegistrationRequest(regEndpoint, metadata, accessToken);

            HTTPResponse httpResponse = request.toHTTPRequest().send();

            if (httpResponse.getStatusCode() == HTTPResponse.SC_OK) {
                OIDCClientInformationResponse clientInfoResponse = OIDCClientInformationResponse.parse(httpResponse); 
                OIDCClientInformation clientInfo = clientInfoResponse.getOIDCClientInformation();
            } else {
                throw new Exception("Client Registration Failed due to invalid registration request");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
