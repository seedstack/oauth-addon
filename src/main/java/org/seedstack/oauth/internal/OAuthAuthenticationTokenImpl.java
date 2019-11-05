/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import com.google.common.base.Preconditions;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import java.util.Optional;
import org.apache.shiro.authc.AuthenticationToken;
import org.seedstack.oauth.spi.OAuthAuthenticationToken;

public class OAuthAuthenticationTokenImpl implements AuthenticationToken, OAuthAuthenticationToken {
    private final AccessToken accessToken;
    private final RefreshToken refreshToken;

    OAuthAuthenticationTokenImpl(AccessToken accessToken, RefreshToken refreshToken) {
        this.accessToken = Preconditions.checkNotNull(accessToken, "Access token cannot be null");
        this.refreshToken = refreshToken;
    }

    OAuthAuthenticationTokenImpl(AccessToken accessToken) {
        this.accessToken = Preconditions.checkNotNull(accessToken, "Access token cannot be null");
        this.refreshToken = null;
    }

    @Override
    public Object getPrincipal() {
        return "";
    }

    @Override
    public Object getCredentials() {
        return accessToken;
    }

    @Override
    public String getAccessToken() {
        return accessToken.getValue();
    }

    @Override
    public Optional<String> getRefreshToken() {
        return Optional.ofNullable(refreshToken).map(RefreshToken::getValue);
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
