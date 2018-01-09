/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import com.google.inject.AbstractModule;
import com.google.inject.util.Providers;
import org.seedstack.oauth.AccessTokenValidator;
import org.seedstack.oauth.OAuthProvider;
import org.seedstack.oauth.OAuthService;

class OAuthModule extends AbstractModule {
    private final OAuthProvider oauthProvider;
    private final Class<? extends AccessTokenValidator> accessTokenValidatorClass;

    OAuthModule(OAuthProvider oauthProvider, Class<? extends AccessTokenValidator> accessTokenValidatorClass) {
        this.oauthProvider = oauthProvider;
        this.accessTokenValidatorClass = accessTokenValidatorClass;
    }

    @Override
    protected void configure() {
        bind(OAuthProvider.class).toInstance(oauthProvider);
        bind(OAuthService.class).to(OAuthServiceImpl.class);
        if (accessTokenValidatorClass != null) {
            bind(AccessTokenValidator.class).to(accessTokenValidatorClass);
        } else {
            bind(AccessTokenValidator.class).toProvider(Providers.of(null));
        }
    }
}
