/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import static com.google.common.base.Preconditions.checkNotNull;

import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import org.seedstack.oauth.OAuthProvider;

class DiscoveredOAuthProvider implements OAuthProvider {
    private final DiscoveryDocument oicDiscoveryDocument;

    DiscoveredOAuthProvider(DiscoveryDocument oicDiscoveryDocument) {
        this.oicDiscoveryDocument = oicDiscoveryDocument;
    }

    @Override
    public boolean isOpenIdCapable() {
        List<String> scopes_supported = oicDiscoveryDocument.getScopes_supported();
        return scopes_supported != null && scopes_supported.contains(OIDCScopeValue.OPENID.getValue());
    }

    @Override
    public Optional<URI> getIssuer() {
        return Optional.ofNullable(oicDiscoveryDocument.getIssuer());
    }

    @Override
    public URI getAuthorizationEndpoint() {
        return checkNotNull(oicDiscoveryDocument.getAuthorization_endpoint(),
                "Authorization endpoint should not be null");
    }

    @Override
    public URI getTokenEndpoint() {
        return checkNotNull(oicDiscoveryDocument.getToken_endpoint(),
                "Token endpoint should not be null");
    }

    @Override
    public Optional<URI> getUserInfoEndpoint() {
        return Optional.ofNullable(oicDiscoveryDocument.getUserinfo_endpoint());
    }

    @Override
    public Optional<URI> getRevocationEndpoint() {
        return Optional.ofNullable(oicDiscoveryDocument.getRevocation_endpoint());
    }
}
