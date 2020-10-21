/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.fixtures.provider;

import org.seedstack.oauth.fixtures.TokenBuilder;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/provider/userInfo")
@Produces(MediaType.APPLICATION_JSON)
public class UserInfoResource {
    @GET
    public Response fetchUserInfo() {
        return Response.ok(userInformation()).build();
    }

    private UserInformation userInformation() {
        UserInformation userInfo = new UserInformation();
        userInfo.setSub(TokenBuilder.SUBJECT_ID);
        userInfo.setGiven_name("Jyoti");
        userInfo.setFamily_name("Athalye");
        userInfo.setName("Jyoti Athalye");
        userInfo.setEmail("myTest@gmail.com");
        userInfo.setPicture("");
        return userInfo;
    }
}

