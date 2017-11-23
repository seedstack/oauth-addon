/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;

import org.seedstack.oauth.AccessTokenValidator;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.OAuthProvider;
import org.seedstack.oauth.TokenValidationException;
import org.seedstack.seed.Configuration;
import org.seedstack.seed.security.AuthenticationException;
import org.seedstack.seed.security.AuthenticationInfo;
import org.seedstack.seed.security.AuthenticationToken;
import org.seedstack.seed.security.Realm;
import org.seedstack.seed.security.RoleMapping;
import org.seedstack.seed.security.RolePermissionResolver;
import org.seedstack.seed.security.principals.PrincipalProvider;
import org.seedstack.seed.security.principals.Principals;
import org.seedstack.seed.security.principals.SimplePrincipalProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
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

public class OAuthRealm implements Realm {
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthRealm.class);
    @Inject
    private OAuthProvider oauthProvider;
    @Inject
    private Provider<AccessTokenValidator> accessTokenValidatorProvider;
    @Inject
    @Named("OAuthRealm-role-mapping")
    private RoleMapping roleMapping;
    @Inject
    @Named("OAuthRealm-role-permission-resolver")
    private RolePermissionResolver rolePermissionResolver;
    @Configuration
    private OAuthConfig oauthConfig;

    @Override
    public Set<String> getRealmRoles(PrincipalProvider<?> identityPrincipal, Collection<PrincipalProvider<?>> otherPrincipals) {
        return new HashSet<>();
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        if (authenticationToken instanceof OAuthAuthenticationToken) {
            AccessToken accessToken = (AccessToken) authenticationToken.getCredentials();
            String subjectId = "";

            if (authenticationToken instanceof OidcAuthenticationToken) {
                JWT idToken = (JWT) authenticationToken.getPrincipal();

                // Validate id and access token using OpenId Connect specification
                IDTokenClaimsSet jwtClaimsSet = validateIdToken(idToken, ((OidcAuthenticationToken) authenticationToken)
                                                .getNonce());
                validateOicdAccessToken(accessToken, idToken.getHeader().getAlgorithm(), 
                                        jwtClaimsSet.getAccessTokenHash());

                // Extract subject id from claim set
                Subject subject = jwtClaimsSet.getSubject();
                if(subject == null){
                    throw new TokenValidationException("Unable to retireve subject from Jwt Claim Set");
                }
                subjectId = subject.getValue();
            } else {
                // Validate access token with custom validator
                AccessTokenValidator accessTokenValidator = accessTokenValidatorProvider.get();
                if (accessTokenValidator != null) {
                    accessTokenValidator.validate(accessToken.getValue());
                } else {
                    throw new TokenValidationException("No access token validator configured");
                }

                // Subject id is unknown
                subjectId = "";
            }

            AuthenticationInfo authenticationInfo = new AuthenticationInfo(subjectId, accessToken);
            fetchUserInfo(accessToken).ifPresent(userInfo -> {
                authenticationInfo.getOtherPrincipals().add(Principals.firstNamePrincipal(userInfo.getGivenName()));
                authenticationInfo.getOtherPrincipals().add(Principals.lastNamePrincipal(userInfo.getFamilyName()));
                authenticationInfo.getOtherPrincipals().add(Principals.fullNamePrincipal(userInfo.getName()));
                authenticationInfo.getOtherPrincipals().add(Principals.localePrincipal(userInfo.getLocale()));
                authenticationInfo.getOtherPrincipals().add(new SimplePrincipalProvider("picture", userInfo.getPicture().toString()));
            });
            return authenticationInfo;
        } else {
            throw new AuthenticationException("OAuthRealm only supports OAuth authentication tokens");
        }
    }

    @Override
    public RoleMapping getRoleMapping() {
        return roleMapping;
    }

    @Override
    public RolePermissionResolver getRolePermissionResolver() {
        return rolePermissionResolver;
    }

    @Override
    public Class<? extends AuthenticationToken> supportedToken() {
        return OAuthAuthenticationToken.class;
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
            throw new TokenValidationException("The received ID token is not intended for this client (audience mismatch)");
        }

        return claims;
    }

    private IDTokenValidator createIdTokenValidator(Issuer expectedIssuer, ClientID clientId, JWT token) {
        if (token instanceof PlainJWT) {
            throw new TokenValidationException("Unsecured JWT token are forbidden");
        } else if (token instanceof EncryptedJWT) {
            throw new TokenValidationException("Encrypted JWT token are not supported");
        } else if (token instanceof SignedJWT) {
            JWSAlgorithm expectedAlgorithm = JWSAlgorithm.parse(oauthProvider.getSigningAlgorithm());
            if (expectedAlgorithm.getName().startsWith("HS")) {
                // HMAC algorithm uses the client secret for validation
                return new IDTokenValidator(expectedIssuer, clientId, expectedAlgorithm, new Secret(oauthConfig.getClientSecret()));
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

    private void validateOicdAccessToken(AccessToken accessToken, Algorithm algorithm, AccessTokenHash accessTokenHash) {

        if (accessToken == null) {
            throw new TokenValidationException("Access Token is not a valid token");
        }

        if (accessTokenHash == null) {
            throw new TokenValidationException("Access Token hash (at_hash claim) is not a valid Hash claim");
        }

        if (algorithm instanceof JWSAlgorithm) {
            JWSAlgorithm expectedAlgorithm = JWSAlgorithm.parse(oauthConfig.getSigningAlgorithm());
            if (!expectedAlgorithm.equals(algorithm)) {
                throw new TokenValidationException("Access token signing algorithm (" + algorithm.getName()
                        + ") does not match the expected algorithm (" + expectedAlgorithm.getName() + ")");
            }

            try {
                com.nimbusds.openid.connect.sdk.validators.AccessTokenValidator.validate(accessToken, (JWSAlgorithm) algorithm, accessTokenHash);
            } catch (InvalidHashException e) {
                throw new TokenValidationException("Failed to validate access token", e);
            }
        } else {
            throw new TokenValidationException("The access token algorithm is not a valid JWS algorithm");
        }
    }

    private Optional<UserInfo> fetchUserInfo(AccessToken accessToken) {
        if (accessToken instanceof BearerAccessToken && oauthProvider.isOpenIdCapable()) {
            Optional<URI> userInfoEndpoint = oauthProvider.getUserInfoEndpoint();
            if (userInfoEndpoint.isPresent()) {
                UserInfoResponse userInfoResponse;
                try {
                    userInfoResponse = UserInfoResponse
                            .parse(new UserInfoRequest(userInfoEndpoint.get(), ((BearerAccessToken) accessToken)).toHTTPRequest().send());
                } catch (IOException | ParseException e) {
                    LOGGER.error("Unable to fetch user info from {}", userInfoEndpoint.get(), e);
                    return Optional.empty();
                }
                if (userInfoResponse.indicatesSuccess()) {
                    return Optional.of(((UserInfoSuccessResponse) userInfoResponse).getUserInfo());
                } else {
                    LOGGER.error("The provider returned an error while fetching user info from {}", userInfoEndpoint.get(),
                            OAuthUtils.buildGenericError(((ErrorResponse) userInfoResponse)));
                    return Optional.empty();
                }
            }
        }
        return Optional.empty();
    }
}
