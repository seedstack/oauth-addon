/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.OAuthProvider;
import org.seedstack.seed.Application;
import org.seedstack.seed.SeedException;

import javax.inject.Inject;
import javax.inject.Provider;
import java.net.URI;
import java.util.List;
import java.util.Optional;

import static com.google.common.base.Preconditions.checkNotNull;

class DiscoveredOAuthProvider implements Provider<OAuthProvider> {
    private final OidcDiscoveryDocument oidcDiscoveryDocument;
    @Inject
    private Application application;

    DiscoveredOAuthProvider(OidcDiscoveryDocument oidcDiscoveryDocument) {
        this.oidcDiscoveryDocument = oidcDiscoveryDocument;
    }

    @Override
    public OAuthProvider get() {
        OAuthConfig oauthConfig = application.getConfiguration().get(OAuthConfig.class);
        return new OAuthProvider() {
            @Override
            public Optional<URI> getIssuer() {
                return Optional.ofNullable(
                        or(
                                oauthConfig.provider().getIssuer(),
                                oidcDiscoveryDocument.getIssuer()
                        )
                );
            }

            @Override
            public URI getAuthorizationEndpoint() {
                return checkNotNull(
                        or(
                                oauthConfig.provider().getAuthorization(),
                                oidcDiscoveryDocument.getAuthorizationEndpoint()
                        ),
                        "Authorization endpoint should not be null"
                );
            }

            @Override
            public URI getTokenEndpoint() {
                return checkNotNull(
                        or(
                                oauthConfig.provider().getToken(),
                                oidcDiscoveryDocument.getTokenEndpoint()
                        ),
                        "Token endpoint should not be null"
                );
            }

            @Override
            public Optional<URI> getUserInfoEndpoint() {
                return Optional.ofNullable(
                        or(
                                oauthConfig.provider().getUserInfo(),
                                oidcDiscoveryDocument.getUserinfoEndpoint()
                        )
                );
            }

            @Override
            public Optional<URI> getRevocationEndpoint() {
                return Optional.ofNullable(
                        or(
                                oauthConfig.provider().getRevocation(),
                                oidcDiscoveryDocument.getRevocationEndpoint()
                        )
                );
            }

            @Override
            public Optional<URI> getJwksEndpoint() {
                return Optional.ofNullable(
                        or(
                                oauthConfig.provider().getJwks(),
                                oidcDiscoveryDocument.getJwksUri()
                        )
                );
            }

            @Override
            public String getIdSigningAlgorithm() {
                List<String> supportedAlgorithms = oidcDiscoveryDocument.getIdTokenSigningAlgValuesSupported();
                String signingAlgorithm = checkNotNull(oauthConfig.algorithms().getIdSigningAlgorithm(),
                        "Expected algorithm not configured");
                if (!supportedAlgorithms.contains(signingAlgorithm)) {
                    throw SeedException.createNew(OAuthErrorCode.SIGNING_ALGORITHM_NOT_SUPPORTED_BY_PROVIDER)
                            .put("requiredAlgorithm", signingAlgorithm)
                            .put("supportedAlgorithms", String.valueOf(supportedAlgorithms));

                }
                return signingAlgorithm;
            }
        };
    }

    private static <T> T or(T first, T second) {
        return first != null ? first : second;
    }
}
