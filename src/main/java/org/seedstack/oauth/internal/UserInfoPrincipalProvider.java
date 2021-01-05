/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.seedstack.seed.security.principals.PrincipalProvider;

class UserInfoPrincipalProvider implements PrincipalProvider<UserInfo> {
    private final UserInfo userInfo;

    UserInfoPrincipalProvider(UserInfo userInfo) {
        this.userInfo = userInfo;
    }

    @Override
    public UserInfo get() {
        return userInfo;
    }
}
