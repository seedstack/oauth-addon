/*
 * Copyright © 2013-2021, The SeedStack authors <http://seedstack.org>
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
import org.seedstack.seed.testing.ConfigurationProfiles;
import org.seedstack.seed.testing.ConfigurationProperty;
import org.seedstack.seed.testing.LaunchMode;
import org.seedstack.seed.testing.LaunchWith;
import org.seedstack.seed.testing.junit4.SeedITRunner;
import org.seedstack.seed.undertow.LaunchWithUndertow;
import org.seedstack.seed.undertow.internal.UndertowLauncher;

import static io.restassured.RestAssured.given;

@RunWith(SeedITRunner.class)
@LaunchWith(value = UndertowLauncher.class, mode = LaunchMode.PER_TEST)
@ConfigurationProfiles(value = "authCode")
public class AuhorizationCodeFlowIT {
    private static final String INCORRECT_STATE_VAL = "KOfmAYYIIZQ_W8OBIWtz3Xs2cWKQqWYtM";
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

        Response response3 = createRequest()
                .log().uri()
                .expect()
                .log().status()
                .statusCode(302)
                .header(LOCATION, Matchers.startsWith(baseUrl + "/api/profile"))
                .when()
                .get(response2.getHeader(LOCATION));
// FIXME: going to the initial URL still redirects to authorization endpoint
//        createRequest()
//                .log().uri()
//                .expect()
//                .log().status()
//                .statusCode(200)
//                .when()
//                .get(response3.getHeader(LOCATION));
    }

    @Test
    @ConfigurationProperty(name = "testConfig.testInvalidNonce", value = "true")
    public void requestShouldFailDueToMismatchInNonce() throws Exception {
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
                .body(Matchers.containsString("Unexpected JWT nonce"))
                .statusCode(401)
                .when()
                .get(response2.getHeader(LOCATION));
    }

    @Test
    @ConfigurationProperty(name = "testConfig.testTokenExpiry", value = "true")
    public void requestShouldFailDueToTokenExpiration() throws Exception {
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
                .statusCode(401)
                .body(Matchers.containsString("Expired JWT"))
                .when()
                .get(response2.getHeader(LOCATION));
    }

    @Test
    @ConfigurationProperty(name = "testConfig.testInvalidAudience", value = "true")
    public void requestShouldFailDueToStateMismatch() throws Exception {
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
                .body(Matchers.containsString("OAuth state mismatch"))
                .statusCode(401)
                .when()
                .get(response2.getHeader(LOCATION));
    }

    @Test
    @ConfigurationProperty(name = "testConfig.testInvalidAudience", value = "true")
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
                .body(Matchers.containsString("Unexpected JWT audience"))
                .statusCode(401)
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
