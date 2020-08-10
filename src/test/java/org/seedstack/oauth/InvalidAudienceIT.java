/*
 * Copyright © 2013-2019, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth;

import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.seedstack.seed.Configuration;
import org.seedstack.seed.testing.ConfigurationProperty;
import org.seedstack.seed.testing.junit4.SeedITRunner;
import org.seedstack.seed.undertow.LaunchWithUndertow;

import static io.restassured.RestAssured.given;

@RunWith(SeedITRunner.class)
@LaunchWithUndertow
@ConfigurationProperty(name = "testConfig.testInvalidAudience", value = "true")
public class InvalidAudienceIT {
    private static final String J_SESSION_ID = "JSESSIONID";
    private static final String LOCATION = "Location";
    private static final String INCORRECT_STATE_VAL = "KOfmAYYIIZQ_W8OBIWtz3Xs2cWKQqWYtM";
    @Configuration("runtime.web.baseUrl")
    private String baseUrl;
    private String jSessionId;

    @Test
    public void requestShouldFailDueToMismatchInStates() throws Exception {
        Response response1 = createRequest()
                .log().uri()
                .expect()
                .log().status()
                .statusCode(302)
                .when()
                .get(baseUrl + "/api/profile");

        extractSessionId(response1);

        Response response2 = createRequest()
                .log().uri()
                .expect()
                .log().status()
                .statusCode(302)
                .when()
                .get(modifyAuthCodeReqWithState(response1.getHeader(LOCATION)));

        createRequest()
                .log().uri()
                .expect()
                .log().status()
                .statusCode(500)
                .when()
                .get(response2.getHeader(LOCATION));
    }

    @Test
    public void requestShouldFailDueToIncorrectTokenAudience() {
        Response response1 = createRequest()
                .log().uri()
                .expect()
                .log().status()
                .statusCode(302)
                .when()
                .get(baseUrl + "/api/profile");

        extractSessionId(response1);

        Response response2 = createRequest()
                .log().uri()
                .expect()
                .log().status()
                .statusCode(302)
                .when()
                .get(response1.getHeader(LOCATION));

        createRequest()
                .log().uri()
                .expect()
                .log().status()
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

    private String modifyAuthCodeReqWithState(String authCodeRequest) {
        int beginIndex = authCodeRequest.indexOf("state=");
        String state = authCodeRequest.substring(beginIndex, authCodeRequest.indexOf("&", beginIndex));
        authCodeRequest = authCodeRequest.replaceAll(state, INCORRECT_STATE_VAL);
        return authCodeRequest;
    }
}
