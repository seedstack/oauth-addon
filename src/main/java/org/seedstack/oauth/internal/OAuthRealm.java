/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.spi.OAuthAuthenticationToken;
import org.seedstack.oauth.spi.OAuthService;
import org.seedstack.oauth.spi.TokenValidationResult;
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

import javax.inject.Inject;
import javax.inject.Named;
import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

public class OAuthRealm implements Realm {
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthRealm.class);
    @Configuration
    private OAuthConfig oAuthConfig;
    @Inject
    private OAuthService oauthService;
    @Inject
    @Named("OAuthRealm-role-mapping")
    private RoleMapping roleMapping;
    @Inject
    @Named("OAuthRealm-role-permission-resolver")
    private RolePermissionResolver rolePermissionResolver;

    @Override
    public Set<String> getRealmPermissions(PrincipalProvider<?> identityPrincipal, Collection<PrincipalProvider<?>> otherPrincipals) {
        if (oAuthConfig.isTreatScopesAsRoles()) {
            return new HashSet<>();
        } else {
            return scopesToStringList(otherPrincipals);
        }
    }

    @Override
    public Set<String> getRealmRoles(PrincipalProvider<?> identityPrincipal,
                                     Collection<PrincipalProvider<?>> otherPrincipals) {
        if (oAuthConfig.isTreatScopesAsRoles()) {
            return scopesToStringList(otherPrincipals);
        } else {
            return new HashSet<>();
        }
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(
            AuthenticationToken authenticationToken) throws AuthenticationException {
        if (authenticationToken instanceof OAuthAuthenticationToken) {
            AccessToken accessToken = (AccessToken) authenticationToken.getCredentials();

            // Validate token to build basic authentication info
            TokenValidationResult result = oauthService.validate(((OAuthAuthenticationToken) authenticationToken));
            AuthenticationInfo authenticationInfo = new AuthenticationInfo(result.getSubjectId(), accessToken);

            // TODO: put id token and refresh token as principals ?

            // Put all claims as principals
            Collection<PrincipalProvider<?>> otherPrincipals = authenticationInfo.getOtherPrincipals();
            result.getClaims().forEach((name, value) -> otherPrincipals.add(new SimplePrincipalProvider(name, value)));

            // Scope as principal (internal principal for role/permission extraction)
            otherPrincipals.add(new ScopePrincipalProvider(new Scope(result.getScopes().toArray(new String[0]))));

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

    private HashSet<String> scopesToStringList(Collection<PrincipalProvider<?>> otherPrincipals) {
        return Optional.ofNullable(Principals.getOnePrincipalByType(otherPrincipals, Scope.class))
                .map(PrincipalProvider::get)
                .map(Scope::toStringList)
                .map(HashSet::new)
                .orElse(new HashSet<>());
    }
}
