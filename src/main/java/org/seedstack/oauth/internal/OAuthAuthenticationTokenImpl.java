/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import com.google.common.base.Preconditions;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.apache.shiro.authc.AuthenticationToken;
import org.seedstack.oauth.OAuthAuthenticationToken;

import java.util.Optional;

public class OAuthAuthenticationTokenImpl implements AuthenticationToken, OAuthAuthenticationToken {
    static final OAuthAuthenticationTokenImpl EMPTY = new OAuthAuthenticationTokenImpl();
    private static final long serialVersionUID = 1L;
    private final AccessToken accessToken;
    private final RefreshToken refreshToken;

    private OAuthAuthenticationTokenImpl() {
        this.accessToken = null;
        this.refreshToken = null;
    }

    OAuthAuthenticationTokenImpl(AccessToken accessToken, RefreshToken refreshToken) {
        this.accessToken = Preconditions.checkNotNull(accessToken, "Access token cannot be null");
        this.refreshToken = refreshToken;
    }

    OAuthAuthenticationTokenImpl(AccessToken accessToken) {
        this.accessToken = Preconditions.checkNotNull(accessToken, "Access token cannot be null");
        this.refreshToken = null;
    }

    @Override
    public String getPrincipal() {
        return "";
    }

    @Override
    public AccessToken getCredentials() {
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

    @Override
    public String toString() {
        return "OAuthAuthenticationToken[?]";
    }
}
