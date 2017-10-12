/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import com.google.common.base.Strings;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import javax.inject.Inject;
import javax.inject.Named;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthResourceResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.seed.Configuration;
import org.seedstack.seed.security.AuthenticationException;
import org.seedstack.seed.security.AuthenticationInfo;
import org.seedstack.seed.security.AuthenticationToken;
import org.seedstack.seed.security.Realm;
import org.seedstack.seed.security.RoleMapping;
import org.seedstack.seed.security.RolePermissionResolver;
import org.seedstack.seed.security.UnsupportedTokenException;
import org.seedstack.seed.security.principals.PrincipalProvider;
import org.seedstack.seed.web.security.WebSecurityConfig;

public class OAuthRealm implements Realm {
    @Inject
    @Named("OAuthRealm-role-mapping")
    private RoleMapping roleMapping;
    @Inject
    @Named("OAuthRealm-role-permission-resolver")
    private RolePermissionResolver rolePermissionResolver;
    @Configuration
    private WebSecurityConfig webSecurityConfig;
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
            String principal = (String) authenticationToken.getPrincipal();
            String accessToken = (String) authenticationToken.getCredentials();
            if (!Strings.isNullOrEmpty(accessToken)) {
                return new AuthenticationInfo(principal, accessToken);
            } else {
                throw new AuthenticationException("Cannot authenticate " + principal);
            }
        } else {
            throw new UnsupportedTokenException("OAuthRealm only supports OAuth authentication tokens");
        }
    }

    private String fetchUserName(OAuthClient oAuthClient, String accessToken) {
        try {
            OAuthClientRequest userInfoRequest = new OAuthBearerClientRequest(oAuthConfig.endpoints().getUserInfo())
                    .setAccessToken(accessToken)
                    .buildQueryMessage();
            return oAuthClient.resource(userInfoRequest,
                    OAuth.HttpMethod.GET,
                    OAuthResourceResponse.class)
                    .getBody();
        } catch (OAuthSystemException | OAuthProblemException e) {
            throw new RuntimeException(e); // TODO
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
}
