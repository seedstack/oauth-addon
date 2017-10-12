/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import com.google.inject.AbstractModule;
import com.google.inject.TypeLiteral;
import com.google.inject.multibindings.Multibinder;
import java.util.List;
import org.seedstack.oauth.AccessTokenValidator;
import org.seedstack.oauth.OAuthProvider;

class OAuthModule extends AbstractModule {
    private final OAuthProvider oAuthProvider;
    private final List<Class<? extends AccessTokenValidator<?>>> accessTokenValidatorClasses;

    OAuthModule(OAuthProvider oAuthProvider,
            List<Class<? extends AccessTokenValidator<?>>> accessTokenValidatorClasses) {
        this.oAuthProvider = oAuthProvider;
        this.accessTokenValidatorClasses = accessTokenValidatorClasses;
    }

    @Override
    protected void configure() {
        bind(OAuthProvider.class).toInstance(oAuthProvider);

        Multibinder<AccessTokenValidator<?>> multibinder = Multibinder.newSetBinder(
                binder(),
                new AccessTokenValidatorTypeLiteral());
        for (Class<? extends AccessTokenValidator<?>> accessTokenValidatorClass : accessTokenValidatorClasses) {
            multibinder.addBinding().to(accessTokenValidatorClass);
        }
    }

    private static class AccessTokenValidatorTypeLiteral extends TypeLiteral<AccessTokenValidator<?>> {}
}
