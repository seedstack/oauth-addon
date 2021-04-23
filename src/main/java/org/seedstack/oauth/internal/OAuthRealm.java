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
import com.nimbusds.openid.connect.sdk.claims.PersonClaims;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.seedstack.oauth.*;
import org.seedstack.seed.Configuration;
import org.seedstack.seed.security.*;
import org.seedstack.seed.security.principals.PrincipalProvider;
import org.seedstack.seed.security.principals.Principals;
import org.seedstack.seed.security.principals.SimplePrincipalProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import java.util.*;

import net.minidev.json.JSONArray;

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
                result.addAll(accessClaimToStrings(otherPrincipals, additionalPermissionsClaim));
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
                result.addAll(accessClaimToStrings(otherPrincipals, additionalRolesClaim));
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

            // Put id claims as simple principals
            claims.forEach((name, value) -> otherPrincipals.add(new SimplePrincipalProvider(name, String.valueOf(value))));

            // Convert some id claims to SeedStack standard principals
            toSimplePrincipal(subjectId, Principals.IDENTITY).ifPresent(otherPrincipals::add);
            toSimplePrincipal(claims.get(PersonClaims.GIVEN_NAME_CLAIM_NAME), Principals.FIRST_NAME).ifPresent(otherPrincipals::add);
            toSimplePrincipal(claims.get(PersonClaims.FAMILY_NAME_CLAIM_NAME), Principals.LAST_NAME).ifPresent(otherPrincipals::add);
            toSimplePrincipal(claims.get(PersonClaims.NAME_CLAIM_NAME), Principals.FULL_NAME).ifPresent(otherPrincipals::add);
            toSimplePrincipal(claims.get(PersonClaims.LOCALE_CLAIM_NAME), Principals.LOCALE).ifPresent(otherPrincipals::add);

            // Put raw userInfo as principal if exists
            if (userInfo != null) {
                otherPrincipals.add(new UserInfoPrincipalProvider(userInfo));
            }

            // Put access claims as principal
            otherPrincipals.add(new AccessClaimsPrincipalProvider(result.getAccessClaims()));

            // Put tokens as principal
            otherPrincipals.add(new TokenPrincipalProvider(result.getToken()));

            // Scope as principal
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

    private Set<String> accessClaimToStrings(Collection<PrincipalProvider<?>> otherPrincipals, String claim) {
        return Optional.ofNullable(Principals.getOnePrincipalByType(otherPrincipals, AccessClaims.class))
                .map(PrincipalProvider::get)
                .map(accessClaims -> accessClaims.get(claim))
                .map(claimObj -> {//changes done to handle users with multiple roles in the form of a JSONArray Jira - IDVS - 10752
                    StringBuilder claimsStr = new StringBuilder("");
                    if (claimObj instanceof JSONArray) {
                        JSONArray array = (JSONArray) claimObj;
                        for (int i = 0; i < array.size(); i++) {
                            claimsStr = claimsStr.append(array.get(i).toString()).append(" ");
                        }
                        return claimsStr.toString();
                    }
                    return claimObj;

                })
                .map(String::valueOf)
                .map(s -> s.split(" "))
                .map(Arrays::asList)
                .map(HashSet::new)
                .orElse(new HashSet<>());

    }
}