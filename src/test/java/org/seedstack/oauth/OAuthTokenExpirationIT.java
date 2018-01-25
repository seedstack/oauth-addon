/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
/*
 * Creation : 13 Dec 2017
 */

package org.seedstack.oauth;

import static io.restassured.RestAssured.given;

import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.seedstack.seed.Configuration;
import org.seedstack.seed.testing.LaunchWith;
import org.seedstack.seed.testing.junit4.SeedITRunner;
import org.seedstack.seed.undertow.internal.UndertowLauncher;

@RunWith(SeedITRunner.class)
@LaunchWith(UndertowLauncher.class)
public class OAuthTokenExpirationIT {
    private static final String J_SESSION_ID = "JSESSIONID";
    private static final String LOCATION = "Location";
    private String jSessionId;
    @Configuration("web.runtime.baseUrl")
    private String baseUrl;

// TODO                .addAsResource("token-expiry-test-config.yaml",
// "META-INF/configuration/token-expiry-test-config.yaml");

    @Test
    public void requestShouldFailDueToTokenExpiration() throws Exception {

        Response response1 = createRequest()
                .expect()
                .statusCode(302)
                .when()
                .get(baseUrl + "api/profile");

        extractSessionId(response1);

        Response response2 = createRequest()
                .expect()
                .statusCode(302)
                .when()
                .get(response1.getHeader(LOCATION));

        createRequest()
                .expect()
                .statusCode(403)
                .when()
                .get(response2.getHeader(LOCATION));

    }

    private void extractSessionId(Response response1) {
        jSessionId = response1.getCookie(J_SESSION_ID);
    }

    private RequestSpecification createRequest() {
        RequestSpecification requestSpecification = given().redirects().follow(false);
        if (jSessionId != null) {
            requestSpecification = requestSpecification.cookie(J_SESSION_ID, jSessionId);
        }
        return requestSpecification;
    }

}
