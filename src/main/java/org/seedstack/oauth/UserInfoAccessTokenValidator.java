/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth;

import com.google.common.base.Strings;
import org.seedstack.seed.Logging;
import org.slf4j.Logger;

import javax.inject.Inject;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
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
            logger.debug("Validating access token by calling userinfo endpoint: {}", uri.toString());
            try {
                HttpURLConnection urlConnection = (HttpURLConnection) uri.toURL().openConnection();
                urlConnection.setRequestProperty("Authorization", "Bearer " + accessToken);
                urlConnection.setRequestMethod("GET");
                urlConnection.setUseCaches(false);

                if (urlConnection.getResponseCode() != 200) {
                    throw new TokenValidationException("Unable to validate the access token (HTTP status " + urlConnection.getResponseCode() + "): " + getErrorBody(urlConnection));
                }
            } catch (IOException e) {
                throw new TokenValidationException("Unable to request the userInfo endpoint", e);
            }
        } else {
            throw new TokenValidationException("No userInfo endpoint configured");
        }
    }

    private String getErrorBody(HttpURLConnection urlConnection) {
        String contentEncoding = urlConnection.getContentEncoding();
        if (Strings.isNullOrEmpty(contentEncoding)) {
            contentEncoding = "UTF-8";
        }
        try (BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getErrorStream(), contentEncoding))) {
            StringBuilder response = new StringBuilder();
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
            return response.toString();
        } catch (IOException e) {
            return "could not read body: " + e.getMessage();
        }
    }
}
