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
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.seedstack.seed.it.AbstractSeedWebIT;

public class OAuthClientCredsGrantIT extends AbstractSeedWebIT{
    
    @ArquillianResource
    private URL baseURL;

    @Deployment
    public static WebArchive createDeployment() {
        return ShrinkWrap.create(WebArchive.class).addAsResource("client-creds-grant-special-config.yaml", "META-INF/configuration/client-creds-grant-special-config.yaml");
    }
    
    @Test
    @RunAsClient
    public void request_to_fetch_access_token_should_succeed() {
         given().expect()
        .statusCode(200)
        .when()
        .get(baseURL.toString() + "profileWithClientCredsGrant.html");
    }

}
