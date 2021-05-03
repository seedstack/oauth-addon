/*
 * Copyright © 2013-2021, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth;

/**
 * Implement this interface to provide a custom validator for OAuth access token. This is only required when NOT using
 * OpenId Connect.
 */
public interface AccessTokenValidator {
    /**
     * This method is called by the security subsystem to validate an opaque access token.
     *
     * @param accessToken the string representation of the token.
     * @throws TokenValidationException if the token is invalid.
     */
    void validate(String accessToken) throws TokenValidationException;
}
