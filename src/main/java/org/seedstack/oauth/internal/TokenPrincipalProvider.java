/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import org.seedstack.oauth.OAuthAuthenticationToken;
import org.seedstack.seed.security.principals.PrincipalProvider;

class TokenPrincipalProvider implements PrincipalProvider<OAuthAuthenticationToken> {
    private final OAuthAuthenticationToken token;

    TokenPrincipalProvider(OAuthAuthenticationToken token) {
        this.token = token;
    }

    @Override
    public OAuthAuthenticationToken get() {
        return token;
    }
}
