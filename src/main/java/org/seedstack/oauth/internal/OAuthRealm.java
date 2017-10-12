/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import javax.inject.Inject;
import javax.inject.Named;
import org.seedstack.oauth.AccessTokenValidator;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.OAuthProvider;
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

public class OAuthRealm implements Realm {
    @Inject
    private Set<AccessTokenValidator<?>> accessTokenValidators;
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

    @Override
    public Set<String> getRealmRoles(PrincipalProvider<?> identityPrincipal,
            Collection<PrincipalProvider<?>> otherPrincipals) {
        return new HashSet<>();
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(
            AuthenticationToken authenticationToken) throws AuthenticationException {
        if (authenticationToken instanceof OAuthAuthenticationToken) {
            Optional<JWT> optionalIdToken = (Optional<JWT>) authenticationToken.getPrincipal();
            String subject = "nobody";
            if (optionalIdToken.isPresent()) {
                // TODO : validate id token
                try {
                    JWTClaimsSet jwtClaimsSet = optionalIdToken.get().getJWTClaimsSet();
                    subject = jwtClaimsSet.getSubject();
                } catch (java.text.ParseException e) {
                    // TODO proper error handling
                    throw new RuntimeException(e);
                }
            }

            final AccessToken accessToken = (AccessToken) authenticationToken.getCredentials();
            // TODO : validate access token

            AuthenticationInfo authenticationInfo = new AuthenticationInfo(subject, accessToken);
            fetchUserInfo(accessToken).ifPresent(userInfo -> {
                authenticationInfo.getOtherPrincipals().add(Principals.firstNamePrincipal(userInfo.getGivenName()));
                authenticationInfo.getOtherPrincipals().add(Principals.lastNamePrincipal(userInfo.getFamilyName()));
                authenticationInfo.getOtherPrincipals().add(Principals.fullNamePrincipal(userInfo.getName()));
                authenticationInfo.getOtherPrincipals().add(Principals.localePrincipal(userInfo.getLocale()));
                authenticationInfo.getOtherPrincipals()
                        .add(new SimplePrincipalProvider("picture", userInfo.getPicture().toString()));
            });

            return authenticationInfo;

        } else {
            throw new UnsupportedTokenException("OAuthRealm only supports OAuth authentication tokens");
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

    private <T> AccessTokenValidator findValidatorFor(T accessToken) {
        for (AccessTokenValidator accessTokenValidator : accessTokenValidators) {
            if (accessTokenValidator.supports(accessToken)) {
                return accessTokenValidator;
            }
        }
        throw SeedException.createNew(OAuthErrorCode.UNABLE_TO_FIND_SUITABLE_ACCESS_TOKEN_VALIDATOR)
                .put("tokenClass", accessToken.getClass());
    }

    private Optional<UserInfo> fetchUserInfo(AccessToken accessToken) {
        if (accessToken instanceof BearerAccessToken
                && oAuthProvider.isOpenIdCapable()
                && oAuthConfig.openIdConnect().isEnabled()) {
            Optional<URI> userInfoEndpoint = oAuthProvider.getUserInfoEndpoint();
            if (userInfoEndpoint.isPresent()) {
                UserInfoResponse userInfoResponse;
                try {
                    userInfoResponse = UserInfoResponse.parse(new UserInfoRequest(
                            userInfoEndpoint.get(),
                            ((BearerAccessToken) accessToken))
                            .toHTTPRequest()
                            .send()
                    );
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
}
