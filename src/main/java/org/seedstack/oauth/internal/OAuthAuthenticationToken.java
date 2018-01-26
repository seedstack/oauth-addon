/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import org.apache.shiro.authc.AuthenticationToken;

public class OAuthAuthenticationToken implements AuthenticationToken, org.seedstack.seed.security.AuthenticationToken {
    private final AccessToken accessToken;

    public OAuthAuthenticationToken(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public Object getPrincipal() {
        return "";
    }

    @Override
    public Object getCredentials() {
        return accessToken;
    }

    /**
     * Returns a textual representation of the authentication token. The access token is omitted for security
     * purposes. The identity is unknown.
     *
     * @return the textual representation as {@link String}.
     */
    @Override
    public String toString() {
        return "OAuthAuthenticationToken[" + getPrincipal() + "]";
    }
}
