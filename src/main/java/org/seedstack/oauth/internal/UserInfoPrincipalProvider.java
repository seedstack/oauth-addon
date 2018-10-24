/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import java.io.Serializable;
import org.seedstack.seed.security.principals.PrincipalProvider;

public class UserInfoPrincipalProvider implements PrincipalProvider<SerializableUserInfo>, Serializable {
    private static final long serialVersionUID = 1L;
    private final SerializableUserInfo userInfo;

    public UserInfoPrincipalProvider(SerializableUserInfo userInfo) {
        this.userInfo = userInfo;
    }

    @Override
    public SerializableUserInfo getPrincipal() {
        return userInfo;
    }
}
