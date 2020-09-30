/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth;

import io.restassured.http.Header;
import org.assertj.core.util.Lists;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.seedstack.oauth.fixtures.TokenBuilder;
import org.seedstack.oauth.fixtures.provider.TokenData;
import org.seedstack.seed.Configuration;
import org.seedstack.seed.testing.junit4.SeedITRunner;
import org.seedstack.seed.undertow.LaunchWithUndertow;

import static io.restassured.RestAssured.given;

@RunWith(SeedITRunner.class)
@LaunchWithUndertow
@Ignore
public class ImplicitFlowIT {
    @Configuration("runtime.web.baseUrl")
    private String baseUrl;
    @Configuration
    private OAuthConfig oauthConfig;

    @Test
    public void requestToAuthoriseUserShouldSucceed() {
        TokenBuilder tokenBuilder = new TokenBuilder(oauthConfig);
        TokenData token = tokenBuilder.buildToken("test", Lists.newArrayList("email", "profile"));
        given()
                .log().uri()
                .header(new Header("Authorization", token.getAccess_token()))
                .expect()
                .log().status()
                .statusCode(200)
                .when()
                .get(baseUrl + "/api/profile");
    }
}
