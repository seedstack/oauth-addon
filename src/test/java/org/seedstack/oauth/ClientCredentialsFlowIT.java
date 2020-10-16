/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.seedstack.oauth.spi.OAuthAuthenticationToken;
import org.seedstack.oauth.spi.OAuthService;
import org.seedstack.seed.Configuration;
import org.seedstack.seed.security.SecuritySupport;
import org.seedstack.seed.security.principals.Principals;
import org.seedstack.seed.testing.ConfigurationProperty;
import org.seedstack.seed.testing.junit4.SeedITRunner;
import org.seedstack.seed.undertow.internal.UndertowLauncher;
import org.seedstack.seed.web.WebConfig;

import javax.inject.Inject;
import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SeedITRunner.class)
// Fake runtime.web.baseUrl config property to allow the oauth add-on to access the mocked identity provider
@ConfigurationProperty(name = "web.server.port", value = "8095")
@ConfigurationProperty(name = "runtime.web.baseUrl", value = "http://localhost:8095")
@ConfigurationProperty(name = "security.oauth.autoFetchUserInfo", value = "true")
public class ClientCredentialsFlowIT {
    private UndertowLauncher launcher = new UndertowLauncher();
    @Configuration
    private WebConfig.ServerConfig serverConfig;
    @Inject
    private OAuthService oauthService;
    @Inject
    private SecuritySupport securitySupport;

    @Before
    public void setUp() throws Exception {
        // Start a second SeedStack application using Undertow which will provide the mocked identity provider
        HashMap<String, String> kernelParameters = new HashMap<>();
        kernelParameters.put("seedstack.config.web.server.port", String.valueOf(serverConfig.getPort()));
        launcher.launch(new String[0], kernelParameters);
    }

    @After
    public void tearDown() throws Exception {
        launcher.shutdown();
    }

    @Test
    public void getAccessTokenFromCredentials() {
        OAuthAuthenticationToken token = oauthService.requestTokensWithClientCredentials();
        oauthService.validate(token);
    }

    @Test
    public void accessUserInfo() {
        OAuthAuthenticationToken token = oauthService.requestTokensWithClientCredentials();
        securitySupport.login(token);

        assertThat(securitySupport.getSimplePrincipalByName(Principals.FIRST_NAME).get()).isEqualTo("Jyoti");
        assertThat(securitySupport.getSimplePrincipalByName(Principals.LAST_NAME).get()).isEqualTo("Athalye");

        securitySupport.logout();
    }
}
