/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import static com.google.common.base.Preconditions.checkNotNull;

import java.net.URI;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Provider;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.OAuthProvider;
import org.seedstack.seed.Application;

class ManualOAuthProvider implements Provider<OAuthProvider> {
    @Inject
    private Application application;

    @Override
    public OAuthProvider get() {
        OAuthConfig oauthConfig = application.getConfiguration().get(OAuthConfig.class);
        return new OAuthProvider() {
            @Override
            public URI getAuthorizationEndpoint() {
                return checkNotNull(oauthConfig.provider().getAuthorization(),
                        "Authorization endpoint should not be null");
            }

            @Override
            public URI getTokenEndpoint() {
                return checkNotNull(oauthConfig.provider().getToken(), "Token endpoint should not be null");
            }

            @Override
            public Optional<URI> getRevocationEndpoint() {
                return Optional.ofNullable(oauthConfig.provider().getRevocation());
            }

            @Override
            public boolean isOpenIdCapable() {
                return oauthConfig.openIdConnect().isEnabled();
            }

            @Override
            public Optional<URI> getIssuer() {
                return Optional.ofNullable(oauthConfig.openIdConnect().getIssuer());
            }

            @Override
            public Optional<URI> getUserInfoEndpoint() {
                return Optional.ofNullable(oauthConfig.openIdConnect().getUserInfo());
            }

            @Override
            public Optional<URI> getJwksEndpoint() {
                return Optional.ofNullable(oauthConfig.openIdConnect().getJwks());
            }

            @Override
            public String getSigningAlgorithm() {
                return checkNotNull(oauthConfig.openIdConnect().getSigningAlgorithm(),
                        "Token signing algorithm should not be null");
            }
        };
    }
}
