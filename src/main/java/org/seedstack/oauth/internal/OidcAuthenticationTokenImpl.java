/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import org.seedstack.oauth.OidcAuthenticationToken;
import org.seedstack.seed.SeedException;

import java.text.ParseException;
import java.util.Map;

import static com.google.common.base.Preconditions.checkNotNull;

public class OidcAuthenticationTokenImpl extends OAuthAuthenticationTokenImpl implements OidcAuthenticationToken {
    private static final long serialVersionUID = 1L;
    private final JWT idToken;
    private final Nonce nonce;
    private final JWTClaimsSet jwtClaimsSet;

    /**
     * Creates an OpenId Connect authentication token.
     *
     * @param accessToken the access token.
     * @param idToken     the id token.
     * @param nonce       the nonce.
     */
    OidcAuthenticationTokenImpl(AccessToken accessToken, RefreshToken refreshToken, JWT idToken, Nonce nonce) {
        super(accessToken, refreshToken);
        this.idToken = checkNotNull(idToken, "id token cannot be null");
        try {
            this.jwtClaimsSet = this.idToken.getJWTClaimsSet();
        } catch (ParseException e) {
            throw SeedException.wrap(e, OAuthErrorCode.INVALID_TOKEN);
        }
        this.nonce = nonce;
    }

    @Override
    public String getPrincipal() {
        return jwtClaimsSet.getSubject();
    }

    @Override
    public String getIdToken() {
        return idToken.serialize();
    }

    @Override
    public Map<String, Object> getIdClaims() {
        return jwtClaimsSet.toJSONObject();
    }

    @Override
    public String toString() {
        return "OidcAuthenticationToken[" + getPrincipal() + "]";
    }

    /**
     * @return the id token as a JWT object.
     */
    JWT getJWTIdToken() {
        return idToken;
    }

    /**
     * Returns the nonce used for the OpenId Connect authentication request.
     *
     * @return the nonce.
     */
    Nonce getNonce() {
        return nonce;
    }
}
