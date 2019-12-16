/*
 * Copyright © 2013-2019, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import java.util.HashMap;
import javax.inject.Inject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.seedstack.oauth.spi.OAuthAuthenticationToken;
import org.seedstack.oauth.spi.OAuthService;
import org.seedstack.seed.security.SecuritySupport;
import org.seedstack.seed.testing.ConfigurationProperty;
import org.seedstack.seed.testing.junit4.SeedITRunner;
import org.seedstack.seed.undertow.internal.UndertowLauncher;

@RunWith(SeedITRunner.class)
// Fake runtime.web.baseUrl config property to allow the oauth add-on to access the mocked identity provider
@ConfigurationProperty(name = "runtime.web.baseUrl", value = "http://localhost:8080")
public class ClientCredentialsFlowIT {
    private UndertowLauncher launcher = new UndertowLauncher();
    @Inject
    private OAuthService oauthService;
    @Inject
    private SecuritySupport securitySupport;

    @Before
    public void setUp() throws Exception {
        // Start a second SeedStack application using Undertow which will provide the mocked identity provider
        launcher.launch(new String[0], new HashMap<>());
    }

    @After
    public void tearDown() throws Exception {
        launcher.shutdown();
    }

    @Test
    public void getAccessTokenFromCredentials() {
        OAuthAuthenticationToken token = oauthService.authenticateWithClientCredentials();
        oauthService.validate(token);
    }

    @Test
    public void accessUserInfo() {
        OAuthAuthenticationToken token = oauthService.authenticateWithClientCredentials();
        securitySupport.login(token);

        UserInfo userInfo = securitySupport.getPrincipalByType(UserInfo.class).get();
        assertThat(userInfo.getGivenName()).isEqualTo("Jyoti");
        assertThat(userInfo.getFamilyName()).isEqualTo("Athalye");

        securitySupport.logout();
    }
}
