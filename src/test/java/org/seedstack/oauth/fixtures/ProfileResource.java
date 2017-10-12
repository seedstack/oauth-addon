/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.fixtures;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import org.seedstack.seed.security.SecuritySupport;
import org.seedstack.seed.security.principals.Principals;

@Path("/profile")
public class ProfileResource {
    @Inject
    private SecuritySupport securitySupport;

    @GET
    @Produces("application/json")
    public ProfileRepresentation sayHello() {
        ProfileRepresentation profileRepresentation = new ProfileRepresentation();
        profileRepresentation
                .setFirstName(securitySupport.getSimplePrincipalByName(Principals.FIRST_NAME).getPrincipal());
        profileRepresentation
                .setLastName(securitySupport.getSimplePrincipalByName(Principals.LAST_NAME).getPrincipal());
        profileRepresentation
                .setFullName(securitySupport.getSimplePrincipalByName(Principals.FULL_NAME).getPrincipal());
        profileRepresentation
                .setPictureUrl(securitySupport.getSimplePrincipalByName("picture").getPrincipal());
        return profileRepresentation;
    }
}
