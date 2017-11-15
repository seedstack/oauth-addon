/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import static com.google.common.base.Preconditions.checkNotNull;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.OAuthProvider;

class ManualOAuthProvider implements OAuthProvider {
    private final OAuthConfig.ProviderConfig providerConfig;

    ManualOAuthProvider(OAuthConfig.ProviderConfig providerConfig) {
        this.providerConfig = providerConfig;
    }

    @Override
    public boolean isOpenIdCapable() {
        return providerConfig.getUserInfo() != null;
    }

    @Override
    public Optional<URI> getIssuer() {
        return Optional.empty();
    }

    @Override
    public URI getAuthorizationEndpoint() {
        return checkNotNull(providerConfig.getAuthorization(), "Authorization endpoint should not be null");
    }

    @Override
    public URI getTokenEndpoint() {
        return checkNotNull(providerConfig.getToken(), "Token endpoint should not be null");
    }

    @Override
    public Optional<URI> getUserInfoEndpoint() {
        return Optional.ofNullable(providerConfig.getUserInfo());
    }

    @Override
    public Optional<URI> getRevocationEndpoint() {
        return Optional.ofNullable(providerConfig.getRevocation());
    }

    @Override
    public List<String> getIdTokenSigningAlgValuesSupported() {
        return checkNotNull(providerConfig.getTokenSigningAlgValues(), "Token signing algorithm should not be null");
    }

    @Override
    public URI getJwksUri() {
        return checkNotNull(providerConfig.getJwksURI(), "Jwks uri should not be null");
    }
}
