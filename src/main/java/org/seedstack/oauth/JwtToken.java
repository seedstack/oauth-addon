/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;

public class JwtToken {

    private JWT id_token;
    private AccessToken access_token;

    public JwtToken(AccessToken access_token, JWT id_token) {
        this.id_token = id_token;
        this.access_token = access_token;
    }

    public JWT getId_token() {
        return this.id_token;
    }

    public AccessToken getAccess_token() {
        return this.access_token;
    }

}
