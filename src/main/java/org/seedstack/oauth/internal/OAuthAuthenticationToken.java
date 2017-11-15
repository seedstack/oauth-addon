/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import java.text.ParseException;
import java.util.Optional;

import org.apache.shiro.authc.AuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;

public class OAuthAuthenticationToken implements AuthenticationToken, org.seedstack.seed.security.AuthenticationToken {
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthAuthenticationToken.class);
    private final JWT idToken;
    private final AccessToken accessToken;
    private Nonce nonce;

    public static Logger getLogger() {
        return LOGGER;
    }

    public JWT getIdToken() {
        return idToken;
    }

    public AccessToken getAccessToken() {
        return accessToken;
    }

    public Optional<Nonce> getNonce() {
        return Optional.ofNullable(nonce);
    }

    public OAuthAuthenticationToken(AccessToken accessToken, JWT idToken, Nonce nonce) {
        this.idToken = idToken;
        this.accessToken = accessToken;
        this.nonce = nonce;
    }

    public OAuthAuthenticationToken(AccessToken accessToken) {
        this.idToken = null;
        this.accessToken = accessToken;
    }

    @Override
    public Object getPrincipal() {
        return Optional.ofNullable(idToken);
    }

    @Override
    public Object getCredentials() {
        return accessToken;
    }

    /**
     * Returns a textual representation of the authentication token. The access token is omitted for security purposes. The identity is extracted from
     * the subject (sub) claim but SHOULD NOT BE TRUSTED as the id token may NOT be validated at this stage.
     *
     * @return the textual representation as {@link String}.
     */
    @Override
    public String toString() {
        if (idToken != null) {
            try {
                return "OAuthAuthenticationToken[" + idToken.getJWTClaimsSet().getSubject() + "]";
            } catch (ParseException e) {
                LOGGER.debug("Unable to parse JWT id token " + idToken.getParsedString());
            }
        }
        return "OAuthAuthenticationToken";
    }
}
