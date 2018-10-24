/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.seedstack.oauth.internal.OAuthUtils.requestTokens;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.IDTokenClaimsVerifier;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import com.nimbusds.openid.connect.sdk.validators.InvalidHashException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Provider;
import org.seedstack.oauth.AccessTokenValidator;
import org.seedstack.oauth.OAuthAuthenticationToken;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.OAuthProvider;
import org.seedstack.oauth.OAuthService;
import org.seedstack.oauth.TokenValidationException;
import org.seedstack.seed.Configuration;
import org.seedstack.seed.security.AuthenticationException;

public class OAuthServiceImpl implements OAuthService {
    @Configuration
    private OAuthConfig oauthConfig;
    @Inject
    private OAuthProvider oauthProvider;
    @Inject
    private Provider<AccessTokenValidator> accessTokenValidatorProvider;

    public OAuthAuthenticationToken authenticateWithClientCredentials(List<String> scopes) {
        return requestTokens(oauthProvider, oauthConfig, new ClientCredentialsGrant(), null, scopes);
    }

    @Override
    public OAuthProvider getOAuthProvider() {
        return oauthProvider;
    }

    @Override
    public Optional<String> validate(OAuthAuthenticationToken authenticationToken) throws AuthenticationException {
        AccessToken accessToken = (AccessToken) checkNotNull(authenticationToken).getCredentials();
        if (authenticationToken instanceof OidcAuthenticationTokenImpl) {
            JWT idToken = (JWT) authenticationToken.getPrincipal();
            IDTokenClaimsSet jwtClaimsSet = validateIdToken(
                    idToken,
                    ((OidcAuthenticationTokenImpl) authenticationToken).getNonce()
            );

            // Validate id and access token using OpenId Connect specification
            validateOicdAccessToken(
                    accessToken,
                    idToken.getHeader().getAlgorithm(),
                    jwtClaimsSet.getAccessTokenHash()
            );

            // Extract subject id from claim set
            Subject subject = jwtClaimsSet.getSubject();
            if (subject == null) {
                throw new TokenValidationException("Unable to retrieve subject from JWT claim set");
            }
            return Optional.of(subject.getValue());
        } else {
            // Validate opaque access token
            validateAccessToken(accessToken);
            return Optional.empty();
        }
    }

    private void validateOicdAccessToken(AccessToken accessToken, Algorithm algorithm,
            AccessTokenHash accessTokenHash) {
        if (accessToken == null) {
            throw new TokenValidationException("Access Token is not a valid token");
        }

        if (algorithm == null) {
            throw new TokenValidationException("Algorithm is invalid (null)");
        }

        if (accessTokenHash == null) {
            throw new TokenValidationException("Access Token hash (at_hash claim) is not a valid hash claim");
        }

        if (algorithm instanceof JWSAlgorithm) {
            JWSAlgorithm expectedAlgorithm = JWSAlgorithm.parse(oauthConfig.getSigningAlgorithm());
            if (!expectedAlgorithm.equals(algorithm)) {
                throw new TokenValidationException("Access token signing algorithm (" + algorithm.getName()
                        + ") does not match the expected algorithm (" + expectedAlgorithm.getName() + ")");
            }
            try {
                com.nimbusds.openid.connect.sdk.validators.AccessTokenValidator
                        .validate(accessToken, (JWSAlgorithm) algorithm, accessTokenHash);
            } catch (InvalidHashException e) {
                throw new TokenValidationException("Failed to validate access token", e);
            }
        } else if (oauthConfig.openIdConnect().isUnsecuredTokenAllowed()) {
            validateAccessToken(accessToken);
        } else {
            throw new TokenValidationException("The access token algorithm is not a valid JWS algorithm");
        }
    }

    private void validateAccessToken(AccessToken accessToken) {
        AccessTokenValidator accessTokenValidator = accessTokenValidatorProvider.get();
        if (accessTokenValidator != null) {
            accessTokenValidator.validate(accessToken.getValue());
        } else {
            throw new TokenValidationException("No access token validator configured");
        }
    }

    private IDTokenClaimsSet validateIdToken(JWT token, Nonce nonce) {
        Issuer expectedIssuer = new Issuer(oauthProvider.getIssuer()
                .orElseThrow(() -> new TokenValidationException("Missing issuer")));
        ClientID clientId = new ClientID(oauthConfig.getClientId());

        // Validate token
        IDTokenClaimsSet claims;
        try {
            claims = createIdTokenValidator(expectedIssuer, clientId, token).validate(token, nonce);
        } catch (BadJOSEException | JOSEException e) {
            throw new TokenValidationException("Failed to validate ID token", e);
        }

        // Verify claims
        try {
            createClaimsVerifier(expectedIssuer, clientId, nonce).verify(claims.toJWTClaimsSet(), null);
        } catch (BadJOSEException | ParseException e) {
            throw new TokenValidationException("Failed to verify ID token claims", e);
        }

        // Check that the token is intended for this client
        List<Audience> audience = claims.getAudience();
        if (!audience.contains(new Audience(clientId))) {
            throw new TokenValidationException(
                    "The received ID token is not intended for this client (audience mismatch)");
        }

        return claims;
    }

    private IDTokenValidator createIdTokenValidator(Issuer expectedIssuer, ClientID clientId, JWT token) {
        if (token instanceof PlainJWT) {
            if (oauthConfig.openIdConnect().isUnsecuredTokenAllowed()) {
                return new IDTokenValidator(expectedIssuer, clientId);
            } else {
                throw new TokenValidationException("Unsecured JWT tokens are forbidden");
            }
        } else if (token instanceof EncryptedJWT) {
            throw new TokenValidationException("Encrypted JWT token are not supported");
        } else if (token instanceof SignedJWT) {
            JWSAlgorithm expectedAlgorithm = JWSAlgorithm.parse(oauthProvider.getSigningAlgorithm());
            if (expectedAlgorithm.getName().startsWith("HS")) {
                // HMAC algorithm uses the client secret for validation
                return new IDTokenValidator(expectedIssuer, clientId, expectedAlgorithm,
                        new Secret(oauthConfig.getClientSecret()));
            } else {
                // Other algorithms uses certificates for validation
                URL jwkSetURL;
                try {
                    jwkSetURL = oauthProvider.getJwksEndpoint()
                            .orElseThrow(() -> new TokenValidationException("Missing JWKS endpoint URI")).toURL();
                } catch (MalformedURLException e) {
                    throw new TokenValidationException("JWKS URI is not a well-formed URL", e);
                }

                return new IDTokenValidator(expectedIssuer, clientId, expectedAlgorithm, jwkSetURL);
            }
        } else {
            throw new TokenValidationException("Unsupported JWT token type");
        }
    }

    private IDTokenClaimsVerifier createClaimsVerifier(Issuer expectedIssuer, ClientID clientId, Nonce nonce) {
        return new IDTokenClaimsVerifier(expectedIssuer, clientId, nonce, 0);
    }
}
