/*
 * Copyright © 2013-2021, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
/*
 * Creation : 20 Nov 2017
 */

package org.seedstack.oauth;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformationResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import java.net.URI;

public class OpenIdConnectClientRegistration {
    private static final String REGISTRATION_END_POINT = "http://127.0.0.1:8080/c2id/clients";
    private static final String BEARER_ACCESS_TKN = "ztucZS1ZyFKgh0tUEruUtiSTXhnexmd6";
    private static final String CALLBACK_URL = "https://127.0.0.1:8081/callback";

    public static void main(String[] args) {
        OpenIdConnectClientRegistration obj = new OpenIdConnectClientRegistration();
        obj.registerClient();
    }

    private void registerClient() {
        try {
            URI regEndpoint = new URI(REGISTRATION_END_POINT);

            OIDCClientMetadata metadata = new OIDCClientMetadata();
            metadata.setRedirectionURI(new URI(CALLBACK_URL));
            metadata.setName("Client Registration App");

            BearerAccessToken accessToken = new BearerAccessToken(BEARER_ACCESS_TKN);

            OIDCClientRegistrationRequest request = new OIDCClientRegistrationRequest(regEndpoint,
                    metadata,
                    accessToken);

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
