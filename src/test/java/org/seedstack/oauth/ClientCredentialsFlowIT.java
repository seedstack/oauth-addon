/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth;

import static org.junit.Assert.assertNotNull;

import javax.inject.Inject;
import org.apache.shiro.authc.AuthenticationToken;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.seedstack.seed.testing.LaunchWith;
import org.seedstack.seed.testing.junit4.SeedITRunner;
import org.seedstack.seed.undertow.internal.UndertowLauncher;

@RunWith(SeedITRunner.class)
@LaunchWith(UndertowLauncher.class)
public class ClientCredentialsFlowIT {
    @Inject
    private OAuthService oauthService;

    @Test
    public void getAccessTokenFromCredentials() {
        AuthenticationToken token = oauthService.getTokenFromClientCredentials();
        assertNotNull(token);
    }
}
