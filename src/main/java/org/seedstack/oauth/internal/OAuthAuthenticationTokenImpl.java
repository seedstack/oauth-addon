/*
 * Copyright © 2013-2021, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import com.google.common.base.Preconditions;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.seedstack.oauth.OAuthAuthenticationToken;

import java.util.Optional;
import java.util.function.Function;

public class OAuthAuthenticationTokenImpl implements AuthenticationToken, OAuthAuthenticationToken {
    static final Function<AuthenticationException, OAuthAuthenticationTokenImpl> ERRORED = OAuthAuthenticationTokenImpl::new;
    private static final long serialVersionUID = 1L;
    private final AccessToken accessToken;
    private final RefreshToken refreshToken;
    private final AuthenticationException exception;

    private OAuthAuthenticationTokenImpl(AuthenticationException e) {
        this.accessToken = null;
        this.refreshToken = null;
        this.exception = e;
    }

    OAuthAuthenticationTokenImpl(AccessToken accessToken, RefreshToken refreshToken) {
        this.accessToken = Preconditions.checkNotNull(accessToken, "Access token cannot be null");
        this.refreshToken = refreshToken;
        this.exception = null;
    }

    OAuthAuthenticationTokenImpl(AccessToken accessToken) {
        this.accessToken = Preconditions.checkNotNull(accessToken, "Access token cannot be null");
        this.refreshToken = null;
        this.exception = null;
    }

    boolean hasException() {
        return exception != null;
    }

    AuthenticationException getException() {
        return exception;
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
