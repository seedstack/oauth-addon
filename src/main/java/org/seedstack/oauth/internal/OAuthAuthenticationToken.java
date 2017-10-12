/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import org.apache.shiro.authc.AuthenticationToken;

public class OAuthAuthenticationToken implements AuthenticationToken, org.seedstack.seed.security.AuthenticationToken {
    private final String principal;
    private final String accessToken;

    public OAuthAuthenticationToken(String principal, String accessToken) {
        this.principal = principal;
        this.accessToken = accessToken;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public Object getCredentials() {
        return accessToken;
    }

}