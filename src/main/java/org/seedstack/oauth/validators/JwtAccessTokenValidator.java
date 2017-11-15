/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.validators;

import org.seedstack.oauth.JwtToken;
import org.seedstack.oauth.TokenValidationException;
import org.seedstack.oauth.TokenValidator;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.validators.AccessTokenValidator;
import com.nimbusds.openid.connect.sdk.validators.InvalidHashException;

public class JwtAccessTokenValidator implements TokenValidator<JwtToken> {

    public static final String AT_HASH_KEY = "at_hash";

    @Override
    public boolean supports(Class<?> token) {
        return JwtToken.class.isAssignableFrom(token);
    }

    @Override
    public void validate(JwtToken token) throws TokenValidationException {
        try {
            AccessTokenValidator.validate(token.getAccess_token(), new JWSAlgorithm(token.getId_token().getHeader().getAlgorithm().toString()),
                    new AccessTokenHash(token.getId_token().getJWTClaimsSet().getClaim(AT_HASH_KEY).toString()));
        } catch (InvalidHashException | java.text.ParseException e) {
            throw new TokenValidationException("Token Validation failed", e);
        }
    }

}
