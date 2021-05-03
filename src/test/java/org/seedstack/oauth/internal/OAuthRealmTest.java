/*
 * Copyright © 2013-2021, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import com.google.common.collect.ImmutableMap;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.assertj.core.util.Lists;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.powermock.reflect.Whitebox;
import org.seedstack.oauth.OAuthAuthenticationToken;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.OAuthService;
import org.seedstack.oauth.TokenValidationResult;
import org.seedstack.oauth.fixtures.TokenBuilder;
import org.seedstack.seed.security.AuthenticationInfo;
import org.seedstack.seed.security.internal.authorization.ConfigurationRoleMapping;
import org.seedstack.seed.security.internal.authorization.ConfigurationRolePermissionResolver;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class OAuthRealmTest {
    private static OAuthAuthenticationToken oAuthAuthenticationToken = new OAuthAuthenticationTokenImpl(new BearerAccessToken(TokenBuilder.ACCESS_TOKEN_VALUE));
    private OAuthRealm underTest;
    private OAuthService oAuthService;
    private OAuthConfig oAuthConfig;

    @Before
    public void setUp() {
        oAuthConfig = new OAuthConfig()
                .setAdditionalPermissionsClaim("perms")
                .setAdditionalRolesClaim("roles");
        oAuthService = Mockito.mock(OAuthService.class);

        underTest = new OAuthRealm();
        Whitebox.setInternalState(underTest, "oAuthConfig", oAuthConfig);
        Whitebox.setInternalState(underTest, "oAuthService", oAuthService);
        Whitebox.setInternalState(underTest, "roleMapping", new ConfigurationRoleMapping());
        Whitebox.setInternalState(underTest, "rolePermissionResolver", new ConfigurationRolePermissionResolver());
    }

    @Test
    public void testStringArrayClaim() {
        mockValidation(ImmutableMap.of("perms", new String[]{"perm4", "perm5"}));
        AuthenticationInfo authenticationInfo = underTest.getAuthenticationInfo(oAuthAuthenticationToken);
        assertThat(underTest.getRealmPermissions(authenticationInfo.getIdentityPrincipal(), authenticationInfo.getOtherPrincipals())).containsExactlyInAnyOrder("scope1", "scope2", "scope3", "perm4", "perm5");
    }

    @Test
    public void testObjectArrayClaim() {
        mockValidation(ImmutableMap.of("perms", new Object[]{new Object() {
            @Override
            public String toString() {
                return "perm4";
            }
        }, "perm5"}));
        AuthenticationInfo authenticationInfo = underTest.getAuthenticationInfo(oAuthAuthenticationToken);
        assertThat(underTest.getRealmPermissions(authenticationInfo.getIdentityPrincipal(), authenticationInfo.getOtherPrincipals())).containsExactlyInAnyOrder("scope1", "scope2", "scope3", "perm4", "perm5");
    }

    @Test
    public void testCollectionClaim() {
        mockValidation(ImmutableMap.of("perms", Lists.newArrayList(new Object() {
            @Override
            public String toString() {
                return "perm4";
            }
        }, "perm5")));
        AuthenticationInfo authenticationInfo = underTest.getAuthenticationInfo(oAuthAuthenticationToken);
        assertThat(underTest.getRealmPermissions(authenticationInfo.getIdentityPrincipal(), authenticationInfo.getOtherPrincipals())).containsExactlyInAnyOrder("scope1", "scope2", "scope3", "perm4", "perm5");
    }

    @Test
    public void testScopesAsPermissions() {
        mockValidation(ImmutableMap.of("perms", new String[]{"perm4", "perm5"}, "roles", new String[]{"role1", "role2"}));
        AuthenticationInfo authenticationInfo = underTest.getAuthenticationInfo(oAuthAuthenticationToken);
        assertThat(underTest.getRealmPermissions(authenticationInfo.getIdentityPrincipal(), authenticationInfo.getOtherPrincipals())).containsExactlyInAnyOrder("scope1", "scope2", "scope3", "perm4", "perm5");
        assertThat(underTest.getRealmRoles(authenticationInfo.getIdentityPrincipal(), authenticationInfo.getOtherPrincipals())).containsExactlyInAnyOrder("role1", "role2");
    }

    @Test
    public void testScopesAsRoles() {
        oAuthConfig.setTreatScopesAsRoles(true);
        mockValidation(ImmutableMap.of("perms", new String[]{"perm4", "perm5"}, "roles", new String[]{"role1", "role2"}));
        AuthenticationInfo authenticationInfo = underTest.getAuthenticationInfo(oAuthAuthenticationToken);
        assertThat(underTest.getRealmPermissions(authenticationInfo.getIdentityPrincipal(), authenticationInfo.getOtherPrincipals())).containsExactlyInAnyOrder("perm4", "perm5");
        assertThat(underTest.getRealmRoles(authenticationInfo.getIdentityPrincipal(), authenticationInfo.getOtherPrincipals())).containsExactlyInAnyOrder("scope1", "scope2", "scope3", "role1", "role2");
    }

    private void mockValidation(Map<String, Object> accessClaims) {
        Mockito.when(oAuthService.validate(oAuthAuthenticationToken)).thenReturn(new TokenValidationResult(
                "id",
                Lists.newArrayList("scope1", "scope2", "scope3"),
                ImmutableMap.of(),
                accessClaims,
                oAuthAuthenticationToken));
    }
}
