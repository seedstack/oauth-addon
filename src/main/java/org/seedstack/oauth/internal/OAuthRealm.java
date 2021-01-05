/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import com.google.common.base.Strings;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.seedstack.oauth.OAuthAuthenticationToken;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.OAuthService;
import org.seedstack.oauth.TokenValidationResult;
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
import java.util.*;

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
            Set<String> result = scopesToStrings(otherPrincipals);
            String additionalPermissionsClaim = oAuthConfig.getAdditionalPermissionsClaim();
            if (!Strings.isNullOrEmpty(additionalPermissionsClaim)) {
                result.addAll(claimToStrings(otherPrincipals, additionalPermissionsClaim));
            }
            return result;
        }
    }

    @Override
    public Set<String> getRealmRoles(PrincipalProvider<?> identityPrincipal, Collection<PrincipalProvider<?>> otherPrincipals) {
        if (oAuthConfig.isTreatScopesAsRoles()) {
            Set<String> result = scopesToStrings(otherPrincipals);
            String additionalRolesClaim = oAuthConfig.getAdditionalRolesClaim();
            if (!Strings.isNullOrEmpty(additionalRolesClaim)) {
                result.addAll(claimToStrings(otherPrincipals, additionalRolesClaim));
            }
            return result;
        } else {
            return new HashSet<>();
        }
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        if (authenticationToken instanceof OAuthAuthenticationTokenImpl) {
            AccessToken accessToken = (AccessToken) authenticationToken.getCredentials();

            // Validate token and extract claims
            TokenValidationResult result = oauthService.validate(((OAuthAuthenticationToken) authenticationToken));
            Map<String, Object> claims = new HashMap<>(result.getClaims());
            String subjectId = result.getSubjectId();
            UserInfo userInfo = null;

            // Override/complete claims with userInfo if fetching is enabled
            if (oAuthConfig.isAutoFetchUserInfo()) {
                Optional<UserInfo> optionalUserInfo = ((OAuthServiceImpl) oauthService).fetchUserInfo(accessToken.getValue());
                if (optionalUserInfo.isPresent()) {
                    userInfo = optionalUserInfo.get();
                    // If tokens didn't provide subject id, use userInfo one (always present)
                    if (result.isAnonymous()) {
                        subjectId = userInfo.getSubject().getValue();
                    }
                    claims.putAll(userInfo.toJSONObject());
                }
            }

            // Build authentication info
            AuthenticationInfo authenticationInfo = new AuthenticationInfo(subjectId, accessToken);
            Collection<PrincipalProvider<?>> otherPrincipals = authenticationInfo.getOtherPrincipals();

            // Put all claims as simple principals
            claims.forEach((name, value) -> otherPrincipals.add(new SimplePrincipalProvider(name, String.valueOf(value))));

            // Convert some claims to SeedStack standard principals
            toSimplePrincipal(subjectId, Principals.IDENTITY).ifPresent(otherPrincipals::add);
            toSimplePrincipal(claims.get(UserInfo.GIVEN_NAME_CLAIM_NAME), Principals.FIRST_NAME).ifPresent(otherPrincipals::add);
            toSimplePrincipal(claims.get(UserInfo.FAMILY_NAME_CLAIM_NAME), Principals.LAST_NAME).ifPresent(otherPrincipals::add);
            toSimplePrincipal(claims.get(UserInfo.NAME_CLAIM_NAME), Principals.FULL_NAME).ifPresent(otherPrincipals::add);
            toSimplePrincipal(claims.get(UserInfo.LOCALE_CLAIM_NAME), Principals.LOCALE).ifPresent(otherPrincipals::add);

            // Put userInfo as principal if exists
            if (userInfo != null) {
                otherPrincipals.add(new UserInfoPrincipalProvider(userInfo));
            }

            // Put tokens as principal
            otherPrincipals.add(new TokenPrincipalProvider(result.getToken()));

            // Scope as principal (internal principal for role/permission extraction)
            otherPrincipals.add(new ScopePrincipalProvider(new Scope(result.getScopes().toArray(new String[0]))));

            return authenticationInfo;
        } else {
            throw new AuthenticationException("OAuthRealm only supports OAuth authentication tokens");
        }
    }

    private Optional<SimplePrincipalProvider> toSimplePrincipal(Object claim, String principalName) {
        if (claim instanceof String) {
            return Optional.of(new SimplePrincipalProvider(principalName, ((String) claim)));
        }
        return Optional.empty();
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

    private Set<String> scopesToStrings(Collection<PrincipalProvider<?>> otherPrincipals) {
        return Optional.ofNullable(Principals.getOnePrincipalByType(otherPrincipals, Scope.class))
                .map(PrincipalProvider::get)
                .map(Scope::toStringList)
                .map(HashSet::new)
                .orElse(new HashSet<>());
    }

    private Set<String> claimToStrings(Collection<PrincipalProvider<?>> otherPrincipals, String claim) {
        return Optional.ofNullable(Principals.getSimplePrincipalByName(otherPrincipals, claim))
                .map(PrincipalProvider::get)
                .map(s -> s.split(" "))
                .map(Arrays::asList)
                .map(HashSet::new)
                .orElse(new HashSet<>());
    }
}
