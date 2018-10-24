/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import java.io.IOException;
import java.io.Serializable;
import java.net.URI;
import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import javax.inject.Inject;
import javax.inject.Named;
import org.seedstack.oauth.OAuthAuthenticationToken;
import org.seedstack.oauth.OAuthProvider;
import org.seedstack.oauth.OAuthService;
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

public class OAuthRealm implements Realm {
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthRealm.class);
    @Inject
    private OAuthService oauthService;
    @Inject
    @Named("OAuthRealm-role-mapping")
    private RoleMapping roleMapping;
    @Inject
    @Named("OAuthRealm-role-permission-resolver")
    private RolePermissionResolver rolePermissionResolver;

    @Override
    public Set<String> getRealmRoles(PrincipalProvider<?> identityPrincipal,
            Collection<PrincipalProvider<?>> otherPrincipals) {
        for (PrincipalProvider<?> principalProvider : otherPrincipals) {
            Serializable principal = principalProvider.getPrincipal();
            if (principal instanceof Scope) {
                return new HashSet<>(((Scope) principal).toStringList());
            }
        }
        throw new IllegalStateException("No scope object found in the principals");
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(
            AuthenticationToken authenticationToken) throws AuthenticationException {
        if (authenticationToken instanceof OAuthAuthenticationToken) {
            AccessToken accessToken = (AccessToken) authenticationToken.getCredentials();

            // Validate token to build basic authentication info
            AuthenticationInfo authenticationInfo =
                    oauthService.validate(((OAuthAuthenticationToken) authenticationToken))
                            .map(subjectId -> new AuthenticationInfo(subjectId, accessToken))
                            .orElse(new AuthenticationInfo("", accessToken));

            Collection<PrincipalProvider<?>> otherPrincipals = authenticationInfo.getOtherPrincipals();

            // Scope as principal
            otherPrincipals.add(new ScopePrincipalProvider(accessToken.getScope()));

            // User info-based principals
            fetchUserInfo(accessToken).ifPresent(userInfo -> {
                // Standard SeedStack principals if present (SDK and realm neutral)
                Optional.ofNullable(userInfo.getGivenName())
                        .map(Principals::firstNamePrincipal)
                        .ifPresent(otherPrincipals::add);
                Optional.ofNullable(userInfo.getFamilyName())
                        .map(Principals::lastNamePrincipal)
                        .ifPresent(otherPrincipals::add);
                Optional.ofNullable(userInfo.getName())
                        .map(Principals::fullNamePrincipal)
                        .ifPresent(otherPrincipals::add);
                Optional.ofNullable(userInfo.getLocale())
                        .map(Principals::localePrincipal)
                        .ifPresent(otherPrincipals::add);

                // Standard claims as principals under their own name (SDK neutral)
                for (String claimName : UserInfo.getStandardClaimNames()) {
                    Optional.ofNullable(userInfo.getStringClaim(claimName))
                            .map(claimValue -> new SimplePrincipalProvider(claimName, claimValue))
                            .ifPresent(otherPrincipals::add);
                }

                // User info object as principal (SDK specific)
                otherPrincipals.add(new UserInfoPrincipalProvider(new SerializableUserInfo(userInfo)));
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
        return OAuthAuthenticationTokenImpl.class;
    }

    private Optional<UserInfo> fetchUserInfo(AccessToken accessToken) {
        OAuthProvider oAuthProvider = oauthService.getOAuthProvider();
        if (accessToken instanceof BearerAccessToken && oAuthProvider.isOpenIdCapable()) {
            Optional<URI> userInfoEndpoint = oAuthProvider.getUserInfoEndpoint();
            if (userInfoEndpoint.isPresent()) {
                UserInfoResponse userInfoResponse;
                URI endpointURI = userInfoEndpoint.get();

                try {
                    userInfoResponse = UserInfoResponse
                            .parse(new UserInfoRequest(endpointURI, ((BearerAccessToken) accessToken))
                                    .toHTTPRequest().send());
                } catch (IOException | ParseException e) {
                    LOGGER.error("Unable to fetch user info from {}", endpointURI, e);
                    return Optional.empty();
                }
                if (userInfoResponse.indicatesSuccess()) {
                    return Optional.of(((UserInfoSuccessResponse) userInfoResponse).getUserInfo());
                } else {
                    LOGGER.error("The provider returned an error while fetching user info from {}",
                            endpointURI,
                            OAuthUtils.buildGenericError(((ErrorResponse) userInfoResponse)));
                    return Optional.empty();
                }
            }
        }
        return Optional.empty();
    }
}
