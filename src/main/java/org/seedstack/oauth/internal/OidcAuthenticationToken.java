/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import static com.google.common.base.Preconditions.checkNotNull;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import java.text.ParseException;

public class OidcAuthenticationToken extends OAuthAuthenticationToken {
    private final JWT idToken;
    private final Nonce nonce;

    /**
     * Creates an OpenId Connect authentication token.
     *
     * @param accessToken the access token.
     * @param idToken     the id token.
     * @param nonce       the nonce.
     */
    public OidcAuthenticationToken(AccessToken accessToken, JWT idToken, Nonce nonce) {
        super(accessToken);
        this.idToken = checkNotNull(idToken, "ID token should not be null");
        this.nonce = nonce;
    }

    @Override
    public Object getPrincipal() {
        return idToken;
    }

    /**
     * Returns the nonce used for the OpenId Connect authentication request.
     *
     * @return the nonce.
     */
    public Nonce getNonce() {
        return nonce;
    }

    /**
     * Returns a textual representation of the authentication token. The access token is omitted for security
     * purposes. The identity is extracted from the subject (sub) claim but SHOULD NOT BE TRUSTED as the id token may
     * NOT be validated at this stage.
     *
     * @return the textual representation as {@link String}.
     */
    @Override
    public String toString() {
        try {
            return "OAuthAuthenticationToken[" + idToken.getJWTClaimsSet().getSubject() + "]";
        } catch (ParseException e) {
            return "OAuthAuthenticationToken[invalid]";
        }
    }
}
