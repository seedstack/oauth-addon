/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import static com.google.common.base.Preconditions.checkNotNull;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;

import org.seedstack.oauth.JwtToken;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.OAuthProvider;
import org.seedstack.oauth.TokenValidationException;
import org.seedstack.oauth.TokenValidator;
import org.seedstack.seed.Configuration;
import org.seedstack.seed.SeedException;
import org.seedstack.seed.security.AuthenticationException;
import org.seedstack.seed.security.AuthenticationInfo;
import org.seedstack.seed.security.AuthenticationToken;
import org.seedstack.seed.security.Realm;
import org.seedstack.seed.security.RoleMapping;
import org.seedstack.seed.security.RolePermissionResolver;
import org.seedstack.seed.security.UnsupportedTokenException;
import org.seedstack.seed.security.principals.PrincipalProvider;
import org.seedstack.seed.security.principals.Principals;
import org.seedstack.seed.security.principals.SimplePrincipalProvider;
import org.seedstack.shed.reflect.Classes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.validators.IDTokenClaimsVerifier;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

public class OAuthRealm implements Realm {

    @Inject
    private OAuthProvider oAuthProvider;
    @Inject
    @Named("OAuthRealm-role-mapping")
    private RoleMapping roleMapping;
    @Inject
    @Named("OAuthRealm-role-permission-resolver")
    private RolePermissionResolver rolePermissionResolver;
    @Configuration
    private OAuthConfig oAuthConfig;

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthRealm.class);

    @Override
    public Set<String> getRealmRoles(PrincipalProvider<?> identityPrincipal, Collection<PrincipalProvider<?>> otherPrincipals) {
        return new HashSet<>();
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        if (authenticationToken instanceof OAuthAuthenticationToken) {
            Optional<JWT> optionalIdToken = (Optional<JWT>) authenticationToken.getPrincipal();
            final AccessToken accessToken = (AccessToken) authenticationToken.getCredentials();
            String subject = "nobody";
            JWT jwtToken = null;

            try {
                Object tokenToValidate;
                if ((optionalIdToken.isPresent())) {
                    jwtToken = optionalIdToken.get();
                    validateJWTToken(jwtToken, ((OAuthAuthenticationToken) authenticationToken).getNonce().orElse(null));
                    tokenToValidate = new JwtToken(accessToken, jwtToken);
                } else {
                    tokenToValidate = accessToken;
                }

                TokenValidator<Object> v = (TokenValidator<Object>) Classes.instantiateDefault(checkNotNull(oAuthConfig.getValidator(), ""));

                if (v.supports(tokenToValidate.getClass())) {
                    v.validate(tokenToValidate);
                } else {
                    throw new TokenValidationException();
                }

            } catch (TokenValidationException e) {
                throw new AuthenticationException("Invalid Token", e);
            }

            AuthenticationInfo authenticationInfo = new AuthenticationInfo(subject, accessToken);
            fetchUserInfo(accessToken).ifPresent(userInfo -> {
                authenticationInfo.getOtherPrincipals().add(Principals.firstNamePrincipal(userInfo.getGivenName()));
                authenticationInfo.getOtherPrincipals().add(Principals.lastNamePrincipal(userInfo.getFamilyName()));
                authenticationInfo.getOtherPrincipals().add(Principals.fullNamePrincipal(userInfo.getName()));
                authenticationInfo.getOtherPrincipals().add(Principals.localePrincipal(userInfo.getLocale()));
                authenticationInfo.getOtherPrincipals().add(new SimplePrincipalProvider("picture", userInfo.getPicture().toString()));
            });

            return authenticationInfo;

        }
        throw new UnsupportedTokenException("OAuthRealm only supports OAuth authentication tokens");
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

    private Optional<UserInfo> fetchUserInfo(AccessToken accessToken) {
        if (accessToken instanceof BearerAccessToken && oAuthProvider.isOpenIdCapable() && oAuthConfig.openIdConnect().isEnabled()) {
            Optional<URI> userInfoEndpoint = oAuthProvider.getUserInfoEndpoint();
            if (userInfoEndpoint.isPresent()) {
                UserInfoResponse userInfoResponse;
                try {
                    userInfoResponse = UserInfoResponse
                            .parse(new UserInfoRequest(userInfoEndpoint.get(), ((BearerAccessToken) accessToken)).toHTTPRequest().send());
                } catch (IOException e) {
                    // TODO proper error handling
                    throw new RuntimeException(e);
                } catch (ParseException e) {
                    // TODO proper error handling
                    throw new RuntimeException(e);
                }
                if (userInfoResponse.indicatesSuccess()) {
                    return Optional.of(((UserInfoSuccessResponse) userInfoResponse).getUserInfo());
                } else {
                    // TODO proper error handling
                }
            }
        }
        return Optional.empty();
    }

    public void validateJWTToken(JWT token, Nonce nonce) {

        try {

            IDTokenValidator validator;
            JWSAlgorithm jwsAlg;

            URL jwkSetURL = oAuthProvider.getJwksUri().toURL();

            if (oAuthProvider.getIdTokenSigningAlgValuesSupported().size() > 1) {
                throw new AuthenticationException("Multiple signing algorithm's not supported for token");
            }
            jwsAlg = new JWSAlgorithm(oAuthProvider.getIdTokenSigningAlgValuesSupported().get(0));

            if (jwsAlg.toString().startsWith("RS")) {
                validator = new IDTokenValidator(new Issuer(oAuthProvider.getIssuer().get()), new ClientID(oAuthConfig.getClientId()), jwsAlg,
                        jwkSetURL);
            } else if (jwsAlg.toString().startsWith("HS")) {
                validator = new IDTokenValidator(new Issuer(oAuthProvider.getIssuer().get()), new ClientID(oAuthConfig.getClientId()), jwsAlg,
                        new Secret(oAuthConfig.getClientSecret()));
            } else {
                throw SeedException.createNew(OAuthErrorCode.UNABLE_TO_FIND_SUITABLE_ACCESS_TOKEN_VALIDATOR).put("tokenClass", token.getClass());
            }

            IDTokenClaimsSet claims = validator.validate(token, nonce);

            IDTokenClaimsVerifier claimVerifier = new IDTokenClaimsVerifier(new Issuer(oAuthProvider.getIssuer().get()),
                    new ClientID(oAuthConfig.getClientId()), null, 0);

            claimVerifier.verify(claims.toJWTClaimsSet(), null);

        } catch (ParseException | MalformedURLException | JOSEException | BadJOSEException e) {
            throw new AuthenticationException("Token Validation Exception", e);
        }
    }

}
