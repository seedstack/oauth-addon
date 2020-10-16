/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth;

import org.seedstack.oauth.spi.AccessTokenValidator;
import org.seedstack.oauth.spi.OAuthProvider;
import org.seedstack.oauth.spi.TokenValidationException;
import org.seedstack.seed.Logging;
import org.slf4j.Logger;

import javax.inject.Inject;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Optional;

/**
 * This class validates the access token by calling the UserInfo endpoint on the OpenIdConnect
 * provider with it.
 */
public class UserInfoAccessTokenValidator implements AccessTokenValidator {
    @Logging
    private Logger logger;
    @Inject
    private OAuthProvider oAuthProvider;

    @Override
    public void validate(String accessToken) throws TokenValidationException {
        Optional<URI> userInfoEndpoint = oAuthProvider.getUserInfoEndpoint();
        if (userInfoEndpoint.isPresent()) {
            URI uri = userInfoEndpoint.get();
            try {
                HttpURLConnection urlConnection = (HttpURLConnection) uri.toURL().openConnection();
                urlConnection.setRequestProperty("Authorization", "Bearer " + accessToken);
                urlConnection.setRequestMethod("GET");
                urlConnection.setUseCaches(false);
                if (urlConnection.getResponseCode() != 200) {
                    throw new TokenValidationException("Unable to validate the access token (HTTP status " + urlConnection.getResponseCode() + ")");
                }
            } catch (IOException e) {
                throw new TokenValidationException("Unable to call the userInfo endpoint", e);
            }
        } else {
            throw new TokenValidationException("No userInfo endpoint configured");
        }
    }
}
