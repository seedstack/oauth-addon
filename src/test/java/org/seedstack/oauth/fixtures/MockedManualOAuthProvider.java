/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.fixtures;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;
import org.seedstack.oauth.OAuthProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MockedManualOAuthProvider implements OAuthProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(MockedManualOAuthProvider.class);

    @Override
    public URI getAuthorizationEndpoint() {
        URI authoriseURI = null;
        try {
            authoriseURI = new URI("http://mockedserver.com/api/provider/authorize");
        } catch (URISyntaxException e) {
            LOGGER.debug("Unable to fetch auth endpoint");
        }
        return authoriseURI;
    }

    @Override
    public URI getTokenEndpoint() {
        URI tokenEndpoint = null;
        try {
            tokenEndpoint = new URI("http://mockedserver.com/api/provider/create-token");
        } catch (URISyntaxException e) {
            LOGGER.debug("Unable to fetch token endpoint");
        }
        return tokenEndpoint;
    }

    @Override
    public Optional<URI> getRevocationEndpoint() {
        URI revokeEndpoint = null;
        try {
            revokeEndpoint = new URI("http://mockedserver.com/api/provider/token/revoke");
        } catch (URISyntaxException e) {
            LOGGER.debug("Unable to fetch revocation endpoint");
        }
        return Optional.of(revokeEndpoint);
    }

    @Override
    public boolean isOpenIdCapable() {
        return true;
    }

    @Override
    public Optional<URI> getIssuer() {
        URI issuerURL = null;
        try {
            issuerURL = new URI("https://mockedserver.com");
        } catch (URISyntaxException e) {
            LOGGER.debug("Unable to fetch issuer");
        }

        return Optional.of(issuerURL);
    }

    @Override
    public Optional<URI> getUserInfoEndpoint() {
        URI userInfoEndpoint = null;
        try {
            userInfoEndpoint = new URI("http://mockedserver.com/api/provider/userInfo");
        } catch (URISyntaxException e) {
            LOGGER.debug("Unable to userinfo endpoint");
        }
        return Optional.of(userInfoEndpoint);
    }

    @Override
    public Optional<URI> getJwksEndpoint() {
        URI jwksEndpoint = null;
        try {
            jwksEndpoint = new URI("https://mockedserver.com/oauth2/v3/certs");
        } catch (URISyntaxException e) {
            LOGGER.debug("Unable to jwks endpoint");
        }
        return Optional.of(jwksEndpoint);
    }

    @Override
    public String getSigningAlgorithm() {
        return "";
    }

}
