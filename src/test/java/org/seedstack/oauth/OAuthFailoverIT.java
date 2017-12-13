/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth;

import static com.jayway.restassured.RestAssured.given;
import java.net.URL;
import org.apache.commons.lang.StringUtils;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.seedstack.seed.it.AbstractSeedWebIT;
import com.jayway.restassured.response.Response;
import com.jayway.restassured.specification.RequestSpecification;


public class OAuthFailoverIT extends AbstractSeedWebIT{
    
    private static final String J_SESSION_ID = "JSESSIONID";
    private static final String LOCATION = "Location";
    private String jSessionId;
    private String INCORRECT_STATE_VAL = "KOfmAYYIIZQ_W8OBIWtz3Xs2cWKQqWYtM";
    
    @ArquillianResource
    private URL baseURL;

    @Deployment
    public static WebArchive createDeployment() {                            
        return ShrinkWrap.create(WebArchive.class)
                .addAsResource("audience-test-config.yaml", "META-INF/configuration/audience-test-config.yaml");
    }
    

    @Test
    @RunAsClient
    public void request_should_fail_due_to_mismatch_in_states() throws Exception {
        Response response1 = createRequest()
                .expect()
                .statusCode(302)
                .when()
                .get(baseURL.toString() + "api/profile");

        extractSessionId(response1);
        
        Response response2 = createRequest()
                .expect()
                .statusCode(302)
                .when()
                .get(modifyAuthCodeReqWithState(response1.getHeader(LOCATION)));
      
                 createRequest()
                .expect()
                .statusCode(500) 
                .when()
                .get(response2.getHeader(LOCATION));
                 
    }
    
    
    @Test
    @RunAsClient
    public void request_should_fail_due_to_incorrect_token_audience(){
        Response response1 = createRequest()
                .expect()
                .statusCode(302)
                .when()
                .get(baseURL.toString() + "api/profile");

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
    
    private String modifyAuthCodeReqWithState(String authCodeRequest){
        String state = StringUtils.substringBetween(authCodeRequest, "state=", "&");
        authCodeRequest = authCodeRequest.replaceAll(state, INCORRECT_STATE_VAL);
        return authCodeRequest;
    }
   
}
