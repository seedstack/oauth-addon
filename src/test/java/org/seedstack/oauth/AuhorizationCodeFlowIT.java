/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth;

import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.seedstack.seed.Configuration;
import org.seedstack.seed.testing.junit4.SeedITRunner;
import org.seedstack.seed.undertow.LaunchWithUndertow;

import static io.restassured.RestAssured.given;

@RunWith(SeedITRunner.class)
@LaunchWithUndertow
public class AuhorizationCodeFlowIT {
    private static final String J_SESSION_ID = "JSESSIONID";
    private static final String LOCATION = "Location";
    private String jSessionId;
    @Configuration("runtime.web.baseUrl")
    private String baseUrl;

    @Test
    public void requestToAuthoriseUserShouldSucceed() {
        Response response1 = createRequest()
                .log().uri()
                .expect()
                .log().status()
                .statusCode(302)
                .header(LOCATION, Matchers.startsWith(baseUrl + "/api/provider/authorize?scope="))
                .when()
                .get(baseUrl + "/api/profile");

        extractSessionId(response1);

        Response response2 = createRequest()
                .log().uri()
                .expect()
                .log().status()
                .statusCode(302)
                .header(LOCATION, Matchers.startsWith(baseUrl + "/callback?code="))
                .when()
                .get(response1.getHeader(LOCATION));

        createRequest()
                .log().uri()
                .expect()
                .log().status()
                .statusCode(302)
                .header(LOCATION, Matchers.startsWith(baseUrl + "/api/profile"))
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
