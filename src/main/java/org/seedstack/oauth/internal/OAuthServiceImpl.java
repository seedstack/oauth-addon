/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.validators.IDTokenClaimsVerifier;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import com.nimbusds.openid.connect.sdk.validators.InvalidHashException;
import net.minidev.json.JSONObject;
import org.seedstack.oauth.AccessTokenValidator;
import org.seedstack.oauth.OAuthAuthenticationToken;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.OAuthProvider;
import org.seedstack.oauth.OAuthService;
import org.seedstack.oauth.TokenValidationException;
import org.seedstack.oauth.TokenValidationResult;
import org.seedstack.seed.Application;
import org.seedstack.seed.Configuration;
import org.seedstack.seed.security.AuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Provider;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.seedstack.oauth.internal.OAuthUtils.createScope;
import static org.seedstack.oauth.internal.OAuthUtils.requestTokens;

public class OAuthServiceImpl implements OAuthService {
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthServiceImpl.class);
    @Configuration
    private OAuthConfig oauthConfig;
    @Inject
    private Application application;
    @Inject
    private OAuthProvider oauthProvider;
    @Inject
    private Provider<AccessTokenValidator> accessTokenValidatorProvider;

    public OAuthAuthenticationToken requestTokensWithClientCredentials(List<String> scopes) throws AuthenticationException {
        LOGGER.debug("Authenticating with client credentials for scopes: {}", scopes);
        return requestTokens(
                oauthProvider,
                oauthConfig,
                new ClientCredentialsGrant(),
                null,
                createScope(scopes)
        );
    }

    @Override
    public OAuthProvider getOAuthProvider() {
        return oauthProvider;
    }

    @Override
    public TokenValidationResult validate(OAuthAuthenticationToken authenticationToken) throws AuthenticationException {
        LOGGER.debug("Validating OAuth tokens for subject {}", authenticationToken.getPrincipal());
        AccessToken accessToken = (AccessToken) checkNotNull(authenticationToken).getCredentials();
        if (authenticationToken instanceof OidcAuthenticationTokenImpl) {
            JWT idToken = ((OidcAuthenticationTokenImpl) authenticationToken).getJWTIdToken();

            // Validate id token
            IDTokenClaimsSet idClaimSet = validateIdToken(
                    idToken,
                    ((OidcAuthenticationTokenImpl) authenticationToken).getNonce()
            );

            // Validate access token
            JWTClaimsSet claimsSet = validateAccessToken(
                    accessToken,
                    idToken.getHeader().getAlgorithm(),
                    idClaimSet.getAccessTokenHash()
            );

            return new TokenValidationResult(
                    idClaimSet.getSubject().getValue(),
                    extractScope(claimsSet),
                    new HashMap<>(idClaimSet.toJSONObject()),
                    new HashMap<>(claimsSet.toJSONObject()),
                    authenticationToken);
        } else {
            // Validate access token
            JWTClaimsSet claimsSet = validateAccessToken(
                    accessToken,
                    JWSAlgorithm.parse(oauthConfig.algorithms().getAccessSigningAlgorithm()),
                    null);

            return new TokenValidationResult(
                    Optional.ofNullable(claimsSet.getSubject()).orElse(""),
                    extractScope(claimsSet),
                    new HashMap<>(),
                    new HashMap<>(claimsSet.toJSONObject()),
                    authenticationToken);
        }
    }

    @Override
    public Map<String, Object> fetchUserInfo(OAuthAuthenticationToken authenticationToken) {
        return new HashMap<>(fetchUserInfo(authenticationToken.getAccessToken()).map(UserInfo::toJSONObject).orElse(new JSONObject()));
    }

    private List<String> extractScope(JWTClaimsSet claimsSet) {
        return Optional.ofNullable(claimsSet.getClaim("scope"))
                .map(Object::toString)
                .map(Scope::parse)
                .orElse(new Scope())
                .toStringList();
    }

    private JWTClaimsSet validateAccessToken(AccessToken accessToken, Algorithm algorithm, AccessTokenHash accessTokenHash) {
        if (accessToken == null) {
            throw new TokenValidationException("No access token provided");
        }

        // Validate token hash if present
        if (accessTokenHash != null && algorithm instanceof JWSAlgorithm) {
            try {
                com.nimbusds.openid.connect.sdk.validators.AccessTokenValidator
                        .validate(accessToken, (JWSAlgorithm) algorithm, accessTokenHash);
            } catch (InvalidHashException e) {
                throw new TokenValidationException("Failed to validate access token: " + e.getMessage(), e);
            }
        }

        try {
            // Parse the token as JWT
            JWT jwt = JWTParser.parse(accessToken.getValue());
            return validateJwtAccessToken(jwt, JWSAlgorithm.parse(oauthConfig.algorithms().getAccessSigningAlgorithm()));
        } catch (java.text.ParseException e) {
            // This exception is thrown when the token is not a JWT at all (so an opaque token)
            LOGGER.debug("Falling back to opaque token validation after token failed to validate as JWT: {}", e.getMessage());
            return validateOpaqueAccessToken(accessToken);
        }
    }

    private JWTClaimsSet validateJwtAccessToken(JWT accessToken, Algorithm algorithm) {
        if (algorithm == null) {
            throw new TokenValidationException("No access token algorithm specified");
        }

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

        // Signing key selector
        oauthProvider.getJwksEndpoint().ifPresent(jwksEndpoint -> {
            try {
                JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(jwksEndpoint.toURL());
                JWSAlgorithm expectedAlg = JWSAlgorithm.parse(oauthConfig.algorithms().getAccessSigningAlgorithm());
                JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedAlg, keySource);
                jwtProcessor.setJWSKeySelector(keySelector);
            } catch (MalformedURLException e) {
                throw new TokenValidationException("Invalid JWKS endpoint: " + e.getMessage());
            }
        });

        // Claims verification
        JWTClaimsSet.Builder exactMatchClaimsBuilder = new JWTClaimsSet.Builder();
        oauthConfig.getExactMatchClaims().forEach(exactMatchClaimsBuilder::claim);

        // Audience verification
        Set<String> allowedAudiences = oauthConfig.getAllowedAudiences();
        if (allowedAudiences != null) {
            allowedAudiences = new HashSet<>(allowedAudiences);
            if (allowedAudiences.isEmpty()) {
                // If no allowed audience is specified, we use the application ID by default
                allowedAudiences.add(application.getId());
            }
        }

        // Configure the processor
        jwtProcessor.setJWTClaimsSetVerifier(
                new DefaultJWTClaimsVerifier<>(
                        allowedAudiences,
                        exactMatchClaimsBuilder.build(),
                        oauthConfig.getRequiredClaims(),
                        oauthConfig.getProhibitedClaims()
                )
        );

        // Execute the validation
        try {
            return jwtProcessor.process(accessToken, null);
        } catch (BadJOSEException | JOSEException e) {
            throw new TokenValidationException("Unable to validate JWT access token: " + e.getMessage(), e);
        }
    }

    private JWTClaimsSet validateOpaqueAccessToken(AccessToken accessToken) {
        AccessTokenValidator accessTokenValidator = accessTokenValidatorProvider.get();
        if (accessTokenValidator != null) {
            accessTokenValidator.validate(accessToken.getValue());
        } else {
            throw new TokenValidationException("No access token validator configured");
        }
        return new JWTClaimsSet.Builder().build();
    }

    private IDTokenClaimsSet validateIdToken(JWT token, Nonce nonce) {
        Issuer expectedIssuer = new Issuer(oauthProvider.getIssuer()
                .orElseThrow(() -> new TokenValidationException("No issuer configured")));
        ClientID clientId = new ClientID(oauthConfig.getClientId());

        // Validate token
        IDTokenClaimsSet claims;
        try {
            claims = createIdTokenValidator(expectedIssuer, clientId, token).validate(token, nonce);
        } catch (BadJOSEException | JOSEException e) {
            throw new TokenValidationException("Failed to validate ID token: " + e.getMessage(), e);
        }

        // Verify claims
        try {
            createIdClaimsVerifier(expectedIssuer, clientId, nonce).verify(claims.toJWTClaimsSet(), null);
        } catch (BadJOSEException | ParseException e) {
            throw new TokenValidationException("Failed to verify ID token claims: " + e.getMessage(), e);
        }

        // Check the token audience
        List<Audience> allowedAudiences = Audience.create(oauthConfig.getClientId());
        if (!Audience.matchesAny(allowedAudiences, claims.getAudience())) {
            throw new TokenValidationException("The received ID token is not intended for this client (audience mismatch)");
        }

        return claims;
    }

    private IDTokenValidator createIdTokenValidator(Issuer expectedIssuer, ClientID clientId, JWT token) {
        if (token instanceof PlainJWT) {
            if (oauthConfig.algorithms().isPlainTokenAllowed()) {
                return new IDTokenValidator(expectedIssuer, clientId);
            } else {
                throw new TokenValidationException("Unsecured JWT tokens are forbidden");
            }
        } else if (token instanceof EncryptedJWT) {
            throw new TokenValidationException("Encrypted JWT token are not supported");
        } else if (token instanceof SignedJWT) {
            JWSAlgorithm expectedAlgorithm = JWSAlgorithm.parse(oauthProvider.getIdSigningAlgorithm());
            if (expectedAlgorithm.getName().startsWith("HS")) {
                // HMAC algorithm uses the client secret for validation
                return new IDTokenValidator(expectedIssuer, clientId, expectedAlgorithm,
                        new Secret(oauthConfig.getClientSecret()));
            } else {
                // Other algorithms uses certificates for validation
                URL jwkSetURL;
                try {
                    jwkSetURL = oauthProvider
                            .getJwksEndpoint()
                            .orElseThrow(() -> new TokenValidationException("Missing JWKS endpoint URI")).toURL();
                } catch (MalformedURLException e) {
                    throw new TokenValidationException("JWKS URI is not a well-formed URL: " + e.getMessage(), e);
                }

                return new IDTokenValidator(expectedIssuer, clientId, expectedAlgorithm, jwkSetURL);
            }
        } else {
            throw new TokenValidationException("Unsupported JWT token type");
        }
    }

    private IDTokenClaimsVerifier createIdClaimsVerifier(Issuer expectedIssuer, ClientID clientId, Nonce nonce) {
        return new IDTokenClaimsVerifier(expectedIssuer, clientId, nonce, 0);
    }

    Optional<UserInfo> fetchUserInfo(String accessToken) {
        Optional<URI> userInfoEndpoint = oauthProvider.getUserInfoEndpoint();
        if (userInfoEndpoint.isPresent()) {
            UserInfoResponse userInfoResponse;
            URI endpointURI = userInfoEndpoint.get();

            try {
                userInfoResponse = UserInfoResponse
                        .parse(new UserInfoRequest(endpointURI, new BearerAccessToken(accessToken))
                                .toHTTPRequest().send());
            } catch (IOException | ParseException e) {
                LOGGER.warn("Unable to fetch user info", e);
                return Optional.empty();
            }
            if (userInfoResponse.indicatesSuccess()) {
                return Optional.of(((UserInfoSuccessResponse) userInfoResponse).getUserInfo());
            } else {
                LOGGER.warn("Unable to fetch user info: {}", OAuthUtils.buildGenericError(((ErrorResponse) userInfoResponse)).getDescription());
                return Optional.empty();
            }
        }
        return Optional.empty();
    }
}
