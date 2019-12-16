/*
 * Copyright © 2013-2019, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import com.google.inject.PrivateModule;
import com.google.inject.util.Providers;
import org.seedstack.oauth.spi.AccessTokenValidator;
import org.seedstack.oauth.spi.OAuthProvider;
import org.seedstack.oauth.spi.OAuthService;

class OAuthModule extends PrivateModule {
    private final OidcDiscoveryDocument discoveryDocument;
    private final Class<? extends AccessTokenValidator> accessTokenValidatorClass;

    OAuthModule(OidcDiscoveryDocument discoveryDocument,
            Class<? extends AccessTokenValidator> accessTokenValidatorClass) {
        this.discoveryDocument = discoveryDocument;
        this.accessTokenValidatorClass = accessTokenValidatorClass;
    }

    @Override
    protected void configure() {
        if (discoveryDocument != null) {
            bind(OAuthProvider.class).toProvider(new DiscoveredOAuthProvider(discoveryDocument));
        } else {
            bind(OAuthProvider.class).toProvider(new ManualOAuthProvider());
        }
        if (accessTokenValidatorClass != null) {
            bind(AccessTokenValidator.class).to(accessTokenValidatorClass);
        } else {
            bind(AccessTokenValidator.class).toProvider(Providers.of(null));
        }
        bind(OAuthService.class).to(OAuthServiceImpl.class);
        expose(OAuthService.class);
    }
}
