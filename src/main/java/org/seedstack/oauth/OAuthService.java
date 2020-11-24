/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth;

import org.seedstack.seed.security.AuthenticationException;
import org.seedstack.seed.security.AuthenticationToken;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Service to interact programmatically with OAuth identity provider. This is useful for machine-to-machine
 * scenarios such as the client credentials flow. It can also be use to manually fetch user information or validate
 * token obtained in a custom manner.
 * <p>
 * For other flows such as authorization code, authorization code with PKCE or implicit flow (deprecated),
 * prefer using with the {@code oauth} and {@code oauthCallback} Web security filters.
 */
public interface OAuthService {
    /**
     * Obtain an authentication token with the configured client credentials. No scopes are requested. Useful for
     * machine-to-machine scenarios. The tokens can then be directly passed to external resource servers or can be
     * used to login locally by passing the returned object to
     * {@link org.seedstack.seed.security.SecuritySupport#login(AuthenticationToken)}.
     *
     * @return the requested tokens wrapped in an {@link OAuthAuthenticationToken}.
     */
    default OAuthAuthenticationToken requestTokensWithClientCredentials() throws AuthenticationException {
        return requestTokensWithClientCredentials(new ArrayList<>());
    }

    /**
     * Obtain an authentication token with the configured client credentials, requesting the specified scopes.
     * Useful for machine-to-machine scenarios. The tokens can then be directly passed to external resource servers
     * or can be used to login locally by passing the returned object to
     * {@link org.seedstack.seed.security.SecuritySupport#login(AuthenticationToken)}.
     *
     * @param scopes the requested scopes.
     * @return the requested tokens wrapped in an {@link OAuthAuthenticationToken}.
     */
    default OAuthAuthenticationToken requestTokensWithClientCredentials(String... scopes) throws AuthenticationException {
        return requestTokensWithClientCredentials(Arrays.asList(scopes));
    }

    /**
     * Obtain an authentication token with the configured client credentials, requesting the specified scopes.
     * Useful for machine-to-machine scenarios. The tokens can then be directly passed to external resource servers
     * or can be used to login locally by passing the returned object to
     * {@link org.seedstack.seed.security.SecuritySupport#login(AuthenticationToken)}.
     *
     * @param scopes the requested scopes.
     * @return the requested tokens wrapped in an {@link OAuthAuthenticationToken}.
     */
    OAuthAuthenticationToken requestTokensWithClientCredentials(List<String> scopes) throws AuthenticationException;

    /**
     * Programmatically validates an {@link OAuthAuthenticationToken}. The access token is always validated, as a JWT
     * or as an opaque token depending on its nature. Opaque access token validation is provider-specific, so it depends
     * on the configured {@link AccessTokenValidator}. If the passed parameter is of type
     * {@link OidcAuthenticationToken}, the identity token is also validated.
     *
     * @param authenticationToken the tokens wrapper to validate.
     * @return the result if the tokens are valid.
     * @throws TokenValidationException if a validation error occurs.
     */
    TokenValidationResult validate(OAuthAuthenticationToken authenticationToken) throws TokenValidationException;

    /**
     * Manually fetches userInfo if such an identity provider endpoint is configured.
     *
     * @param authenticationToken the token used to access the authentication token.
     * @return the user info claims.
     */
    Map<String, Object> fetchUserInfo(OAuthAuthenticationToken authenticationToken);

    /**
     * @return the configured {@link OAuthProvider}.
     */
    OAuthProvider getOAuthProvider();
}
