/*
 * Copyright © 2013-2021, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth;

import org.seedstack.seed.security.AuthenticationToken;

import java.util.Optional;

public interface OAuthAuthenticationToken extends AuthenticationToken {
    /**
     * @return the access token as a string.
     */
    String getAccessToken();

    /**
     * @return the refresh token as a string if any.
     */
    Optional<String> getRefreshToken();

}
