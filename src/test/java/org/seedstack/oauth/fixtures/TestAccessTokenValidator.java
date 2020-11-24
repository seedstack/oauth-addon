/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.fixtures;

import org.seedstack.oauth.AccessTokenValidator;
import org.seedstack.oauth.TokenValidationException;

public class TestAccessTokenValidator implements AccessTokenValidator {
    @Override
    public void validate(String accessToken) throws TokenValidationException {
        if (!TokenBuilder.ACCESS_TOKEN_VALUE.equals(accessToken)) {
            throw new TokenValidationException("Access token is not valid");
        }
    }
}
